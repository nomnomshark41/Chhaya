#![allow(clippy::module_name_repetitions)]

use std::io;

use crate::{HandshakeConfirm, HandshakeInit, HandshakeResp, RetryCookie};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    request_response::{
        self, InboundFailure, InboundRequestId, OutboundFailure, OutboundRequestId,
    },
    PeerId,
};
use serde::{Deserialize, Serialize};

/// Maximum size for any single exchange frame (1 MiB).
pub const MAX_FRAME_SIZE: usize = 1 << 20;
const PROTOCOL_NAME: &str = "/chhaya/exchange/1";

/// Request-response protocol used for handshake material exchange.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExchangeProtocol;

impl AsRef<str> for ExchangeProtocol {
    fn as_ref(&self) -> &str {
        PROTOCOL_NAME
    }
}

/// Outbound messages sent by the initiator over the exchange protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExchangeRequest {
    HandshakeInit(Box<HandshakeInit>),
    HandshakeConfirm(HandshakeConfirm),
}

/// Responses returned by the responder across the exchange protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExchangeResponse {
    HandshakeResp(HandshakeResp),
    HandshakeConfirm(HandshakeConfirm),
    Retry(RetryCookie),
}

/// Events emitted by the exchange behaviour for consumer state machines.
#[derive(Clone, Debug)]
pub enum ExchangeEvent {
    InboundRequest {
        peer: PeerId,
        request_id: InboundRequestId,
        request: ExchangeRequest,
    },
    InboundFailure {
        peer: PeerId,
        request_id: InboundRequestId,
        error: ExchangeInboundError,
    },
    ResponseSent {
        peer: PeerId,
        request_id: InboundRequestId,
    },
}

/// Normalised inbound failures surfaced by libp2p's request-response behaviour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExchangeInboundError {
    Timeout,
    ConnectionClosed,
    UnsupportedProtocols,
    ResponseOmission,
    Io(String),
}

impl From<InboundFailure> for ExchangeInboundError {
    fn from(value: InboundFailure) -> Self {
        match value {
            InboundFailure::Timeout => Self::Timeout,
            InboundFailure::ConnectionClosed => Self::ConnectionClosed,
            InboundFailure::UnsupportedProtocols => Self::UnsupportedProtocols,
            InboundFailure::ResponseOmission => Self::ResponseOmission,
            InboundFailure::Io(err) => Self::Io(err.to_string()),
        }
    }
}

/// Errors returned to callers when performing handshake exchanges.
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    #[error("dial failure")]
    DialFailure,
    #[error("request timed out")]
    Timeout,
    #[error("connection closed before response")]
    ConnectionClosed,
    #[error("remote peer rejected protocol")]
    UnsupportedProtocol,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("exchange task stopped")]
    ChannelClosed,
    #[error("response channel closed")]
    ResponseChannelClosed,
    #[error("unknown inbound request {0}")]
    UnknownInbound(InboundRequestId),
}

impl From<OutboundFailure> for ExchangeError {
    fn from(value: OutboundFailure) -> Self {
        match value {
            OutboundFailure::DialFailure => Self::DialFailure,
            OutboundFailure::Timeout => Self::Timeout,
            OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            OutboundFailure::Io(err) => Self::Io(err),
        }
    }
}

/// Identifier for inbound handshake requests.
pub type InboundExchangeId = InboundRequestId;
/// Identifier for outbound handshake requests.
pub type OutboundExchangeId = OutboundRequestId;

/// CBOR codec implementing the exchange protocol wire format.
#[derive(Clone, Default)]
pub struct ExchangeCodec;

#[async_trait]
impl request_response::Codec for ExchangeCodec {
    type Protocol = ExchangeProtocol;
    type Request = ExchangeRequest;
    type Response = ExchangeResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_frame(io).await?;
        decode_message(&bytes)
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_frame(io).await?;
        decode_message(&bytes)
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_message(&req)?;
        write_frame(io, &bytes).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let bytes = encode_message(&res)?;
        write_frame(io, &bytes).await
    }
}

fn decode_message<T>(bytes: &[u8]) -> io::Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_cbor::from_slice(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn encode_message<T>(message: &T) -> io::Result<Vec<u8>>
where
    T: Serialize,
{
    let bytes = serde_cbor::to_vec(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exchange frame exceeds maximum size",
        ));
    }
    Ok(bytes)
}

async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0_u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exchange frame exceeds maximum size",
        ));
    }
    let mut data = vec![0_u8; len];
    io.read_exact(&mut data).await?;
    Ok(data)
}

async fn write_frame<T>(io: &mut T, data: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if data.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exchange frame exceeds maximum size",
        ));
    }
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(data).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TestVkdKeys;
    use futures::io::Cursor;
    use libp2p::request_response::Codec as _;

    fn sample_init() -> HandshakeInit {
        let (record, _) = crate::generate_directory_record::<crate::MlKem1024>(
            b"did:example:alice".to_vec(),
            42,
            crate::sample_quorum_desc(42),
        )
        .expect("generate record");
        let spend = crate::make_receipt(record.prekey_batch_root);
        let keys = TestVkdKeys::single_witness();
        let vkd = crate::make_vkd_proof(&record, &keys);
        let (init, _) =
            crate::initiator_handshake_init::<crate::MlKem1024>(&record, spend, None, vkd)
                .expect("handshake init");
        init
    }

    fn sample_resp() -> HandshakeResp {
        HandshakeResp {
            nonce: [9_u8; 12],
            confirm_tag: vec![1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn roundtrip_request() {
        let request = ExchangeRequest::HandshakeInit(Box::new(sample_init()));
        let expected = match &request {
            ExchangeRequest::HandshakeInit(init) => (**init).clone(),
            _ => unreachable!(),
        };
        let mut codec = ExchangeCodec;
        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_request(&ExchangeProtocol, &mut buffer, request.clone())
            .await
            .expect("write request");
        buffer.set_position(0);
        let decoded = codec
            .read_request(&ExchangeProtocol, &mut buffer)
            .await
            .expect("read request");
        match decoded {
            ExchangeRequest::HandshakeInit(init) => {
                assert_eq!(init.did, expected.did);
                assert_eq!(init.epoch, expected.epoch);
                assert_eq!(init.kem_ciphertext, expected.kem_ciphertext);
                assert_eq!(init.sth_cid, expected.sth_cid);
                assert_eq!(init.bundle_cid, expected.bundle_cid);
            }
            _ => panic!("unexpected request variant"),
        }
    }

    #[tokio::test]
    async fn roundtrip_response() {
        let response = ExchangeResponse::HandshakeResp(sample_resp());
        let mut codec = ExchangeCodec;
        let mut buffer = Cursor::new(Vec::new());
        codec
            .write_response(&ExchangeProtocol, &mut buffer, response)
            .await
            .expect("write response");
        buffer.set_position(0);
        let decoded = codec
            .read_response(&ExchangeProtocol, &mut buffer)
            .await
            .expect("read response");
        match decoded {
            ExchangeResponse::HandshakeResp(resp) => {
                assert_eq!(resp.confirm_tag, vec![1, 2, 3, 4]);
            }
            _ => panic!("unexpected response variant"),
        }
    }

    #[tokio::test]
    async fn enforces_frame_limit() {
        let mut codec = ExchangeCodec;
        let mut buffer = Cursor::new(Vec::new());
        let oversized_len = u32::try_from(MAX_FRAME_SIZE + 1).expect("frame length fits u32");
        buffer
            .get_mut()
            .extend_from_slice(&oversized_len.to_be_bytes());
        buffer
            .get_mut()
            .extend_from_slice(&vec![0_u8; MAX_FRAME_SIZE + 1]);
        buffer.set_position(0);
        let result = codec.read_response(&ExchangeProtocol, &mut buffer).await;
        assert!(result.is_err(), "expected frame size error");
    }
}
