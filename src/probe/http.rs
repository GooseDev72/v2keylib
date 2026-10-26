//! HTTP reachability probes (HEAD preferred, GET available but unrecommended).

use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::node::Node;

const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";

fn client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true)
        .user_agent("v2keylib/0.1")
        .build()
        .map_err(|e| Error::Probe(e.to_string()))
}

/// Probe URL for a node.
///
/// An explicit override always wins. Otherwise the request must go to *the
/// node itself*, so:
/// * SNI/Host present -> that domain over https,
/// * IP address only    -> plain http to that IP (plain http so no certificate
///   is needed; a middlebox answering it still counts as "reachable", which is
///   exactly the caveat of using http-get for liveness).
pub fn probe_url(node: &Node, override_url: Option<&str>) -> String {
    if let Some(url) = override_url {
        return url.to_string();
    }
    let domain = node
        .sni
        .clone()
        .or_else(|| node.transport.host.clone().map(|h| h.split(',').next().unwrap_or("").trim().to_string()))
        .filter(|s| !s.is_empty())
        .filter(|s| s.parse::<std::net::IpAddr>().is_err());
    match domain {
        Some(d) => format!("https://{d}/generate_204"),
        None => format!("http://{}/generate_204", crate::links::vless::host_part(&node.address)),
    }
}

/// Fallback endpoint for nodes whose address cannot be reached over HTTP.
pub const FALLBACK_URL: &str = DEFAULT_URL;

/// Any status below 500 counts as "reachable"; 5xx means something answered
/// but is not a working tunnel endpoint.
pub async fn http_probe(
    node: &Node,
    method: reqwest::Method,
    timeout: Duration,
    url: Option<&str>,
) -> Result<Duration> {
    let target = probe_url(node, url);
    let client = client(timeout)?;
    let start = Instant::now();
    let mut req = client.request(method, &target);
    if let Some(host) = node.sni.as_deref().or(node.transport.host.as_deref()) {
        let host = host.split(',').next().unwrap_or(host).trim();
        if !host.is_empty() {
            req = req.header("Host", host);
        }
    }
    let resp = req
        .send()
        .await
        .map_err(|e| Error::Probe(format!("{target}: {e}")))?;
    let status = resp.status();
    let elapsed = start.elapsed();
    if status.is_server_error() {
        return Err(Error::Probe(format!("{target}: http {}", status.as_u16())));
    }
    Ok(elapsed)
}

pub async fn head_probe(node: &Node, timeout: Duration, url: Option<&str>) -> Result<Duration> {
    http_probe(node, reqwest::Method::HEAD, timeout, url).await
}

pub async fn get_probe(node: &Node, timeout: Duration, url: Option<&str>) -> Result<Duration> {
    http_probe(node, reqwest::Method::GET, timeout, url).await
}
