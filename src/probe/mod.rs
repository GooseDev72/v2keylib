//! Liveness probes: TCP connect, ICMP ping, HTTP HEAD/GET.
//!
//! All probes are cheap reachability signals, not protocol handshakes: a node
//! can pass a probe and still be broken, so use them to *sort and prune* large
//! key lists cheaply, never as a proof of work.

pub mod http;
pub mod icmp;

use std::net::SocketAddr;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::node::Node;

/// Which check to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// TCP handshake only — cheapest, recommended default.
    Tcp,
    /// ICMP echo (needs raw socket privileges for true ping).
    Icmp,
    /// TLS-less HTTP HEAD to the probe URL host.
    HttpHead,
    /// HTTP GET — heavier, and can be answered by a middlebox: unrecommended.
    HttpGet,
}

impl ProbeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeKind::Tcp => "tcp",
            ProbeKind::Icmp => "icmp",
            ProbeKind::HttpHead => "http-head",
            ProbeKind::HttpGet => "http-get",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" | "connect" => Ok(ProbeKind::Tcp),
            "icmp" | "ping" => Ok(ProbeKind::Icmp),
            "http-head" | "head" => Ok(ProbeKind::HttpHead),
            "http-get" | "get" => Ok(ProbeKind::HttpGet),
            other => Err(Error::Probe(format!("unknown probe: {other}"))),
        }
    }
}

/// Probe settings.
#[derive(Clone, Debug)]
pub struct ProbeOptions {
    pub timeout: Duration,
    pub concurrency: usize,
    /// Stop after this many live nodes (0 = no limit).
    pub limit: usize,
    /// Fail fast: abort the whole run at the first dead node.
    pub fail_fast: bool,
    /// URL used for HTTP probes; defaults to a 204 endpoint on the node's SNI.
    pub probe_url: Option<String>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            concurrency: 64,
            limit: 0,
            fail_fast: false,
            probe_url: None,
        }
    }
}

/// Result of probing one node.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub index: usize,
    pub alive: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

/// Run one probe against a node according to `kind`.
pub async fn probe_node(node: &Node, kind: ProbeKind, opts: &ProbeOptions) -> Result<Duration> {
    match kind {
        ProbeKind::Tcp => {
            let addr = resolve(node).await?;
            tcp_probe(addr, opts.timeout).await
        }
        ProbeKind::Icmp => icmp::icmp_probe(node, opts.timeout).await,
        ProbeKind::HttpHead => http::head_probe(node, opts.timeout, opts.probe_url.as_deref()).await,
        ProbeKind::HttpGet => http::get_probe(node, opts.timeout, opts.probe_url.as_deref()).await,
    }
}

/// Resolve a node address to a socket address, using DNS if needed.
pub async fn resolve(node: &Node) -> Result<SocketAddr> {
    if let Ok(ip) = node.address.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, node.port));
    }
    let host = node.address.clone();
    let port = node.port;
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        let mut addrs = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| Error::Probe(format!("dns {host}: {e}")))?;
        addrs
            .find(|a| matches!(a, SocketAddr::V4(_) | SocketAddr::V6(_)))
            .ok_or_else(|| Error::Probe(format!("dns {host}: no address")))
    })
    .await
    .map_err(|e| Error::Probe(e.to_string()))?
}

/// Plain TCP connect check.
pub async fn tcp_probe(addr: SocketAddr, timeout: Duration) -> Result<Duration> {
    let start = std::time::Instant::now();
    let connect = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr));
    match connect.await {
        Ok(Ok(_stream)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(Error::Probe(e.to_string())),
        Err(_) => Err(Error::Probe(format!("timeout after {:?}", timeout))),
    }
}
