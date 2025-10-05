// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use cid::Cid;
use reqwest::{Client, StatusCode, Url};
use thiserror::Error;

/// HTTP endpoint details for a trusted IPFS gateway.
#[derive(Clone, Debug)]
pub struct KuboGateway {
    endpoint: Url,
    timeout: Duration,
}

/// Errors encountered while deriving gateway endpoints from user input.
#[derive(Debug, Error)]
pub enum GatewayConfigError {
    #[error("invalid gateway base url {url}: {message}")]
    Parse { url: String, message: String },
    #[error("failed to derive block/get endpoint from {base}: {message}")]
    Endpoint { base: String, message: String },
}

impl KuboGateway {
    pub fn new(mut base: Url, timeout: Duration) -> Result<Self, GatewayConfigError> {
        if base.path().is_empty() {
            base.set_path("/");
        }
        if !base.path().ends_with('/') {
            let mut path = base.path().to_string();
            if !path.ends_with('/') {
                path.push('/');
            }
            base.set_path(&path);
        }
        let base_display = base.to_string();
        let endpoint = base
            .join("block/get")
            .map_err(|error| GatewayConfigError::Endpoint {
                base: base_display,
                message: error.to_string(),
            })?;
        Ok(Self { endpoint, timeout })
    }

    pub fn from_str(url: &str, timeout: Duration) -> Result<Self, GatewayConfigError> {
        let parsed = Url::parse(url).map_err(|error| GatewayConfigError::Parse {
            url: url.to_string(),
            message: error.to_string(),
        })?;
        Self::new(parsed, timeout)
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Failure raised by the direct IPFS block fetch implementation.
#[derive(Debug, Clone, Error)]
#[error("direct fetch failed: {message}")]
pub struct DirectBlockFetchError {
    message: String,
}

impl DirectBlockFetchError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Captures a single gateway error for diagnostics.
#[derive(Debug, Clone)]
pub struct GatewayFailure {
    pub endpoint: Url,
    pub error: GatewayError,
}

/// High-level failure modes when talking to a gateway.
#[derive(Debug, Clone)]
pub enum GatewayError {
    Request {
        message: String,
    },
    Status {
        status: StatusCode,
        body: Option<String>,
    },
}

impl fmt::Display for GatewayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request { message } => write!(f, "request error: {message}"),
            Self::Status { status, body } => {
                write!(f, "unexpected status {status}")?;
                if let Some(body) = body {
                    if !body.is_empty() {
                        write!(f, " ({body})")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for GatewayError {}

/// Aggregate outcome when all block retrieval strategies are exhausted.
#[derive(Debug)]
pub enum BlockFetchError {
    NoGateways {
        direct: Option<DirectBlockFetchError>,
    },
    Exhausted {
        direct: Option<DirectBlockFetchError>,
        gateways: Vec<GatewayFailure>,
    },
}

impl BlockFetchError {
    pub fn direct_failure(&self) -> Option<&DirectBlockFetchError> {
        match self {
            Self::NoGateways { direct } | Self::Exhausted { direct, .. } => direct.as_ref(),
        }
    }

    pub fn gateway_failures(&self) -> &[GatewayFailure] {
        match self {
            Self::NoGateways { .. } => &[],
            Self::Exhausted { gateways, .. } => gateways,
        }
    }
}

impl fmt::Display for BlockFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoGateways { direct } => {
                write!(f, "no HTTP gateways configured after direct fetch")?;
                match direct {
                    Some(err) => write!(f, " failure: {err}"),
                    None => f.write_str(" returned no data"),
                }
            }
            Self::Exhausted { direct, gateways } => {
                write!(f, "all block fetch attempts failed")?;
                if let Some(err) = direct {
                    write!(f, "; direct fetch error: {err}")?;
                } else {
                    write!(f, "; direct fetch returned no data")?;
                }
                if !gateways.is_empty() {
                    write!(f, "; gateway errors: ")?;
                    for (index, failure) in gateways.iter().enumerate() {
                        if index > 0 {
                            f.write_str(", ")?;
                        }
                        write!(f, "{} ({})", failure.endpoint, failure.error)?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for BlockFetchError {}

/// Builder errors for [`BlockFetcher`] construction.
#[derive(Debug, Error)]
pub enum BlockFetcherBuildError {
    #[error("failed to build HTTP client: {0}")]
    HttpClient(#[from] reqwest::Error),
}

/// Pluggable interface for attempting a direct block fetch before gateways.
#[async_trait]
pub trait DirectBlockFetcher: Send + Sync {
    async fn try_fetch_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, DirectBlockFetchError>;
}

/// Block fetcher that falls back from direct retrieval to HTTP gateways.
pub struct BlockFetcher<D>
where
    D: DirectBlockFetcher,
{
    direct: D,
    client: Client,
    gateways: Vec<KuboGateway>,
}

impl<D> BlockFetcher<D>
where
    D: DirectBlockFetcher,
{
    pub fn new(direct: D, gateways: Vec<KuboGateway>) -> Result<Self, BlockFetcherBuildError> {
        let client = Client::builder().user_agent("chhaya-ipfs/0.1").build()?;
        Ok(Self::with_client(direct, client, gateways))
    }

    pub fn with_client(direct: D, client: Client, gateways: Vec<KuboGateway>) -> Self {
        Self {
            direct,
            client,
            gateways,
        }
    }

    pub async fn fetch_block(&self, cid: &Cid) -> Result<Vec<u8>, BlockFetchError> {
        let mut direct_error = None;
        match self.direct.try_fetch_block(cid).await {
            Ok(Some(bytes)) => return Ok(bytes),
            Ok(None) => {}
            Err(err) => direct_error = Some(err),
        }

        if self.gateways.is_empty() {
            return Err(BlockFetchError::NoGateways {
                direct: direct_error,
            });
        }

        let cid_string = cid.to_string();
        let mut failures = Vec::with_capacity(self.gateways.len());
        for gateway in &self.gateways {
            match self.fetch_from_gateway(gateway, &cid_string).await {
                Ok(bytes) => return Ok(bytes),
                Err(error) => failures.push(GatewayFailure {
                    endpoint: gateway.endpoint().clone(),
                    error,
                }),
            }
        }

        Err(BlockFetchError::Exhausted {
            direct: direct_error,
            gateways: failures,
        })
    }

    async fn fetch_from_gateway(
        &self,
        gateway: &KuboGateway,
        cid: &str,
    ) -> Result<Vec<u8>, GatewayError> {
        let request = self
            .client
            .post(gateway.endpoint().clone())
            .query(&[("arg", cid)])
            .timeout(gateway.timeout());
        let response = request
            .send()
            .await
            .map_err(|error| GatewayError::Request {
                message: error.to_string(),
            })?;
        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_else(|_| String::new());
            return Err(GatewayError::Status {
                status,
                body: if body_text.is_empty() {
                    None
                } else {
                    Some(truncate_body(&body_text))
                },
            });
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| GatewayError::Request {
                message: error.to_string(),
            })?;
        Ok(bytes.to_vec())
    }
}

fn truncate_body(body: &str) -> String {
    const MAX_LEN: usize = 256;
    if body.len() <= MAX_LEN {
        body.to_string()
    } else {
        let mut truncated = body[..MAX_LEN].to_string();
        truncated.push('…');
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use reqwest::Client;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct MockDirect {
        responses: Mutex<VecDeque<Result<Option<Vec<u8>>, DirectBlockFetchError>>>,
    }

    impl MockDirect {
        fn new(responses: Vec<Result<Option<Vec<u8>>, DirectBlockFetchError>>) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from(responses)),
            }
        }
    }

    #[async_trait]
    impl DirectBlockFetcher for MockDirect {
        async fn try_fetch_block(
            &self,
            _cid: &Cid,
        ) -> Result<Option<Vec<u8>>, DirectBlockFetchError> {
            let mut guard = self.responses.lock().expect("poisoned");
            guard.pop_front().unwrap_or(Ok(None))
        }
    }

    async fn spawn_mock_gateway(body: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0_u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if buf[..n].windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            }
        });
        (addr, handle)
    }

    fn sample_cid() -> Cid {
        Cid::try_from("bafkreigh2akiscaildc3nj5mzq6y3yzlwgthhzgm4xg2xiz3oyn2nqumoy").expect("cid")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn returns_direct_result_when_available() {
        let direct = MockDirect::new(vec![Ok(Some(b"direct".to_vec()))]);
        let fetcher = BlockFetcher::with_client(direct, Client::new(), Vec::new());
        let cid = sample_cid();
        let data = fetcher.fetch_block(&cid).await.expect("fetch");
        assert_eq!(data, b"direct");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn falls_back_to_gateway_on_direct_failure() {
        let body = b"gateway".to_vec();
        let (addr, handle) = spawn_mock_gateway(body.clone()).await;
        let base = format!("http://{addr}/api/v0/");
        let gateway = KuboGateway::from_str(&base, Duration::from_secs(2)).expect("gateway");
        let direct = MockDirect::new(vec![Err(DirectBlockFetchError::new("dial failed"))]);
        let fetcher = BlockFetcher::with_client(direct, Client::new(), vec![gateway]);
        let cid = sample_cid();
        let data = fetcher.fetch_block(&cid).await.expect("fetch");
        assert_eq!(data, body);
        handle.await.expect("server");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tries_multiple_gateways_until_success() {
        let body = b"second".to_vec();
        let (addr, handle) = spawn_mock_gateway(body.clone()).await;
        let bad_gateway =
            KuboGateway::from_str("http://127.0.0.1:9/api/v0/", Duration::from_millis(100))
                .expect("bad gateway");
        let good_base = format!("http://{addr}/api/v0/");
        let good_gateway =
            KuboGateway::from_str(&good_base, Duration::from_secs(2)).expect("good gateway");
        let direct = MockDirect::new(vec![Ok(None)]);
        let fetcher =
            BlockFetcher::with_client(direct, Client::new(), vec![bad_gateway, good_gateway]);
        let cid = sample_cid();
        let data = fetcher.fetch_block(&cid).await.expect("fetch");
        assert_eq!(data, body);
        handle.await.expect("server");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reports_failures_when_all_attempts_exhausted() {
        let direct_error = DirectBlockFetchError::new("timeout");
        let gateway_one =
            KuboGateway::from_str("http://127.0.0.1:9/api/v0/", Duration::from_millis(100))
                .expect("gateway");
        let gateway_two =
            KuboGateway::from_str("http://127.0.0.1:10/api/v0/", Duration::from_millis(100))
                .expect("gateway");
        let fetcher = BlockFetcher::with_client(
            MockDirect::new(vec![Err(direct_error.clone())]),
            Client::new(),
            vec![gateway_one, gateway_two],
        );
        let cid = sample_cid();
        let err = fetcher.fetch_block(&cid).await.expect_err("error");
        match err {
            BlockFetchError::Exhausted { direct, gateways } => {
                if let Some(actual) = direct {
                    assert_eq!(actual.to_string(), direct_error.to_string());
                } else {
                    panic!("expected direct error");
                }
                assert_eq!(gateways.len(), 2);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn errors_without_gateways() {
        let fetcher =
            BlockFetcher::with_client(MockDirect::new(vec![Ok(None)]), Client::new(), Vec::new());
        let cid = sample_cid();
        let err = fetcher.fetch_block(&cid).await.expect_err("error");
        match err {
            BlockFetchError::NoGateways { direct } => assert!(direct.is_none()),
            other => panic!("unexpected error: {other}"),
        }
    }
}
