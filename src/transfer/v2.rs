#![allow(dead_code)]

use futures::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use sha2::{digest::FixedOutput, Digest, Sha256};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf};

/*
 * Normal transfer:
 * - Write files into temporary folder, move at the end
 * - Keep symlink to folder somewhere, to recognize resumable transfers
 * - Only keep last folder around, purge it on next transfer
 * Resumption recognition:
 * - Only check offer against received data
 * - If matches name send length
 * - Remove entries that don't match
 * Automatic resumption?
 * - Keep Wormhole alive
 * - If transfer fails, connect to same mailbox and re-start transit foo
 */

use super::*;

/**
 * A set of hints for both sides to find each other
 */
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TransitV2 {
    pub hints_v2: transit::Hints,
}

/**
 * The type of message exchanged over the transit connection, serialized with msgpack
 */
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PeerMessageV2 {
    Offer(OfferMessage),
    Answer(Answer),
    FileStart(FileStart),
    Payload(Payload),
    FileEnd(FileEnd),
    TransferAck(TransferAck),
    Error(String),
    #[serde(other)]
    Unknown,
}

impl PeerMessageV2 {
    pub fn ser_msgpack(&self) -> Vec<u8> {
        let mut writer = Vec::with_capacity(128);
        let mut ser = rmp_serde::encode::Serializer::new(&mut writer)
            .with_struct_map()
            .with_human_readable();
        serde::Serialize::serialize(self, &mut ser).unwrap();
        writer
    }

    pub fn de_msgpack(data: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_read(&mut &*data)
    }

    pub fn check_err(self) -> Result<Self, TransferError> {
        match self {
            Self::Error(err) => Err(TransferError::PeerError(err)),
            other => Ok(other),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct OfferMessage {
    pub transfer_name: Option<String>,
    pub content: OfferContent,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct OfferContent {
    pub name: String,
    pub mtime: u64,
    #[serde(flatten)]
    pub inner: OfferContentInner,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum OfferContentInner {
    RegularFile {
        size: u64,
        id: u64,
    },
    Directory {
        content: Vec<OfferContent>,
    },
    Symlink {
        target: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Answer {
    pub files: Vec<AnswerInner>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct AnswerInner {
    pub file: String,
    pub offset: u64,
    pub hash: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct FileStart {
    pub id: u64,
    pub start_at_offset: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Payload {
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct FileEnd {
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TransferAck {
}

#[allow(unused_variables, unused_mut)]
pub async fn send<C, F, H>(
    mut wormhole: Wormhole,
    relay_hints: Vec<transit::RelayHint>,
    offer: &Offer,
    content: C,
    progress_handler: H,
    peer_version: AppVersion,
) -> Result<(), TransferError>
where
    C: FnMut(&str) -> F,
    F: AsyncRead + AsyncSeek + Unpin,
    H: FnMut(u64, u64) + 'static,
{
    let peer_abilities = peer_version.transfer_v2.unwrap();
    let mut actual_transit_abilities = transit::Abilities::ALL_ABILITIES;
    actual_transit_abilities.intersect(&peer_abilities.transit_abilities);
    let connector = transit::init(actual_transit_abilities, Some(peer_abilities.transit_abilities), relay_hints).await?;

    /* Send our transit hints */
    wormhole
    .send_json(
        &PeerMessage::transit_v2(
            (**connector.our_hints()).clone().into(),
        ),
    )
    .await?;

    /* Receive their transit hints */
    let their_hints: transit::Hints =
        match wormhole.receive_json::<PeerMessage>().await??.check_err()? {
            PeerMessage::TransitV2(transit) => {
                debug!("received transit message: {:?}", transit);
                transit.hints_v2.into()
            },
            other => {
                let error = TransferError::unexpected_message("transit-v2", other);
                let _ = wormhole
                    .send_json(&PeerMessage::Error(format!("{}", error)))
                    .await;
                bail!(error)
            },
        };

    /* Get a transit connection */
    let (mut transit, _info, _addr) = match connector
        .leader_connect(
            wormhole.key().derive_transit_key(wormhole.appid()),
            peer_abilities.transit_abilities,
            Arc::new(their_hints),
        )
        .await
    {
        Ok(transit) => transit,
        Err(error) => {
            let error = TransferError::TransitConnect(error);
            let _ = wormhole
                .send_json(&PeerMessage::Error(format!("{}", error)))
                .await;
            return Err(error);
        },
    };

    /* Close the Wormhole and switch to using the transit connection (msgpack instead of json) */
    wormhole.close().await?;

    match send_inner(
        &mut transit,
        &offer,
        content,
        progress_handler,
    ).await {
        Ok(()) => (),
        Err(error @ TransferError::PeerError(_)) => bail!(error),
        Err(error) => {
            let _ = transit
                .send_record(&PeerMessageV2::Error(format!("{}", error)).ser_msgpack())
                .await;
            bail!(error)
        },
    }

    Ok(())
}

/** We've established the transit connection and closed the Wormhole */
async fn send_inner<C, F, H>(
    transit: &mut transit::Transit,
    offer: &OfferContent,
    mut content: C,
    mut progress_handler: H,
) -> Result<(), TransferError>
where
    C: FnMut(&str) -> F,
    F: AsyncRead + AsyncSeek + Unpin,
    H: FnMut(u64, u64) + 'static,
{
    transit.send_record(&PeerMessageV2::Offer(OfferMessage {
        transfer_name: None,
        content: offer.clone(),
    }).ser_msgpack()).await?;

    let files = match PeerMessageV2::de_msgpack(&transit.receive_record().await?)?.check_err()? {
        PeerMessageV2::Answer(answer) => {
            answer.files
        },
        other => {
            bail!(TransferError::unexpected_message("answer", other))
        },
    };

    // use zstd::stream::raw::Encoder;
    // let zstd = Encoder::new(zstd::DEFAULT_COMPRESSION_LEVEL);
    let mut buffer = Box::new([0u8; 16 * 1024]);

    for AnswerInner {file, offset, hash} in &files {
        let mut offset = *offset;
        let mut content = content(file);

        /* If they specified a hash, check our local file's contents */
        if let Some(hash) = hash {
            content.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut hasher = Sha256::default();
            async_std::io::copy(
                content.take(offset),
                futures::io::AllowStdIo::new(&mut hasher),
            ).await?;
            let our_hash = hasher.finalize_fixed();

            /* If it doesn't match, start at 0 instead of the originally requested offset */
            if our_hash == hash {
                transit.send_record(
                    &PeerMessageV2::FileStart(FileStart { id: file, start_at_offset: true }).ser_msgpack()
                ).await?;
            } else {
                transit.send_record(
                    &PeerMessageV2::FileStart(FileStart { id: file, start_at_offset: false }).ser_msgpack()
                ).await?;
                content.seek(std::io::SeekFrom::Start(0)).await?;
                offset = 0;
            }
        } else {
            content.seek(std::io::SeekFrom::Start(offset)).await?;
            transit.send_record(
                &PeerMessageV2::FileStart(FileStart { id: file, start_at_offset: true }).ser_msgpack()
            ).await?;
        }

        let mut sent_size = 0;
        loop {
            let n = content.read(&mut buffer[..]).await?;
            let buffer = &buffer[..n];

            if n == 0 {
                // EOF
                break;
            }

            transit.send_record(
                &PeerMessageV2::Payload(Payload { payload: buffer.into() }).ser_msgpack()
            ).await?;
            sent_size += n as u64;
            progress_handler(sent_size, todo!());

            if n < 4096 {
                break;
            }
        }
        transit.send_record(
            &PeerMessageV2::FileEnd(FileEnd {}).ser_msgpack()
        ).await?;
    }
    transit.send_record(
        &PeerMessageV2::TransferAck(TransferAck {}).ser_msgpack()
    ).await?;

    Ok(())
}

pub async fn request_offer(
    mut wormhole: Wormhole,
    relay_hints: Vec<transit::RelayHint>,
    peer_version: AppVersion,
) -> Result<ReceiveRequest, TransferError> {
    let peer_abilities = peer_version.transfer_v2.unwrap();
    let mut actual_transit_abilities = transit::Abilities::ALL_ABILITIES;
    actual_transit_abilities.intersect(&peer_abilities.transit_abilities);
    let connector = transit::init(actual_transit_abilities, Some(peer_abilities.transit_abilities), relay_hints).await?;

    /* Send our transit hints */
    wormhole
    .send_json(
        &PeerMessage::transit_v2(
            (**connector.our_hints()).clone().into(),
        ),
    )
    .await?;

    /* Receive their transit hints */
    let their_hints: transit::Hints =
        match wormhole.receive_json::<PeerMessage>().await??.check_err()? {
            PeerMessage::TransitV2(transit) => {
                debug!("received transit message: {:?}", transit);
                transit.hints_v2.into()
            },
            other => {
                let error = TransferError::unexpected_message("transit-v2", other);
                let _ = wormhole
                    .send_json(&PeerMessage::Error(format!("{}", error)))
                    .await;
                bail!(error)
            },
        };

    /* Get a transit connection */
    let (mut transit, _info, _addr) = match connector
        .leader_connect(
            wormhole.key().derive_transit_key(wormhole.appid()),
            peer_abilities.transit_abilities,
            Arc::new(their_hints),
        )
        .await
    {
        Ok(transit) => transit,
        Err(error) => {
            let error = TransferError::TransitConnect(error);
            let _ = wormhole
                .send_json(&PeerMessage::Error(format!("{}", error)))
                .await;
            return Err(error);
        },
    };

    /* Close the Wormhole and switch to using the transit connection (msgpack instead of json) */
    wormhole.close().await?;

    let offer = match PeerMessageV2::de_msgpack(&transit.receive_record().await?)?.check_err()? {
        PeerMessageV2::Offer(offer) => offer,
        other => {
            bail!(TransferError::unexpected_message("offer", other))
        },
    };

    Ok(ReceiveRequest::new(transit, offer))
}

pub(super) struct ReceiveRequest {
    transit: Transit,
    offer: Arc<Offer>,
}

impl ReceiveRequest {
    pub fn new(transit: Transit, offer: Offer) -> Self {
        Self {
            transit,
            offer: Arc::new(offer),
        }
    }

    pub fn offer(&self) -> &Arc<Offer> {
        &self.offer
    }

    pub async fn accept<W>(
        mut self,
        mut offsets: impl FnMut(&str) -> Option<AnswerInner>,
        content: impl FnMut(&str) -> W,
        progress_handler: impl FnMut(u64, u64) + 'static,
    ) -> Result<(), TransferError>
    where
        W: AsyncWrite + AsyncSeek + Unpin
    {
        let files: Vec<AnswerInner> = self.offer.list_file_paths()
            .filter_map(|file| offsets(&file))
            .collect();
        self.transit.send_record(
            &PeerMessageV2::Answer(Answer {
                files: files.clone(),
            }).ser_msgpack()
        ).await?;

        receive_inner(
            &mut self.transit,
            &self.offer,
            content,
            progress_handler,
        ).await
    }

    pub async fn reject(mut self) -> Result<(), TransferError> {
        self.transit.send_record(
            &PeerMessageV2::Error("transfer rejected".into()).ser_msgpack()
        ).await?;
        self.transit.flush().await?;

        Ok(())
    }
}

/** We've established the transit connection and closed the Wormhole */
async fn receive_inner<C, F, H>(
    transit: &mut transit::Transit,
    offer: &Arc<Offer>,
    mut content: C,
    mut progress_handler: H,
) -> Result<(), TransferError>
where
    C: FnMut(&str) -> F,
    F: AsyncWrite + AsyncSeek + Unpin,
    H: FnMut(u64, u64) + 'static,
{
/*
    for i in 0..todo!() {
        let mut content = content(i);
        let fileStart = match PeerMessageV2::de_msgpack(&transit.receive_record().await?)?.check_err()? {
            PeerMessageV2::FileStart(fileStart) => fileStart,
            other => {
                bail!(TransferError::unexpected_message("offer", other))
            },
        };
        let mut received_size = 0;
        if fileStart.start_at_offset {
            let offset = todo!();
            content.seek(std::io::SeekFrom::Start(offset)).await?;
            received_size = offset;
        } else {
            content.seek(std::io::SeekFrom::Start(0)).await?;
        }

        loop {
            let payload = match PeerMessageV2::de_msgpack(&transit.receive_record().await?)?.check_err()? {
                PeerMessageV2::Payload(payload) => payload.payload,
                other => {
                    bail!(TransferError::unexpected_message("payload", other))
                },
            };

            content.write_all(&payload).await?;
            received_size += payload.len() as u64;

            if true {
                break
            }
        }

        let end = match PeerMessageV2::de_msgpack(&transit.receive_record().await?)?.check_err()? {
            PeerMessageV2::FileEnd(end) => end,
            other => {
                bail!(TransferError::unexpected_message("file-end", other))
            },
        };
    }*/

    todo!()
}
