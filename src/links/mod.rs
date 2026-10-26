//! Proxy link (`vless://`, `vmess://`, ...) parsing and rendering.

pub mod hysteria;
pub mod trojan;
pub mod vless;
pub mod vmess;

use crate::error::{Error, Result};
use crate::node::{Node, Protocol};
use crate::util::RawLink;




/// Parser/renderer for one URI scheme.
pub trait LinkCodec {
    fn parse(link: &str) -> Result<Node>;
    fn render(node: &Node) -> Result<String>;
}

/// Parse any supported `scheme://...` link into a [`Node`].
pub fn parse(link: &str) -> Result<Node> {
    let link = link.trim();
    if link.is_empty() {
        return Err(Error::MalformedLink("empty link".into()));
    }
    if !link.contains("://") {
        return Err(Error::MalformedLink(format!(
            "not a proxy link: {}",
            crate::util::truncate_public(link)
        )));
    }
    let scheme = link
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| Error::UnsupportedScheme(link.trim().to_string()))?;
    let codec: fn(&str) -> Result<Node> = match scheme.as_str() {
        "vless" => vless::parse_str,
        "vmess" => vmess::parse_str,
        "trojan" | "trojan-go" => trojan::parse_str,
        "hysteria" | "hy" => hysteria::parse_v1_str,
        "hysteria2" | "hy2" => hysteria::parse_v2_str,
        "ss" | "shadowsocks" => shadowsocks::parse,
        "tuic" => tuic::parse,
        "socks" | "socks5" => socks::parse,
        "anytls" => anytls::parse,
        other => return Err(Error::UnsupportedScheme(other.to_string())),
    };
    codec(link)
}

/// Render a [`Node`] back into its canonical link.
pub fn render(node: &Node) -> Result<String> {
    // Annotations this library made for its own use are not part of the link,
    // so they are dropped before it is built rather than emitted as parameters
    // no server reads.
    let node = node.clone().without_annotations();
    let node = &node;
    match node.protocol {
        Protocol::Vless => vless::render(node),
        Protocol::Vmess => vmess::render(node),
        Protocol::Trojan => trojan::render(node),
        Protocol::Hysteria => hysteria::render_v1(node),
        Protocol::Hysteria2 => hysteria::render_v2(node),
        Protocol::Shadowsocks => shadowsocks::render(node),
        Protocol::Tuic => tuic::render(node),
        Protocol::Socks => socks::render(node),
        Protocol::Http => Err(Error::UnsupportedProtocol("http".into())),
        Protocol::Wireguard => Err(Error::UnsupportedProtocol("wireguard".into())),
        Protocol::Anytls => anytls::render(node),
    }
}

/// Render many nodes as a newline-separated link list.
///
/// A node that cannot be rendered is skipped with a warning rather than
/// failing the batch: one unsupported node should not cost you the other
/// thousand. Use [`render_all_checked`] when you need to know.
pub fn render_all(nodes: &[Node]) -> Result<String> {
    let (text, failed) = render_all_checked(nodes)?;
    for (node, error) in failed {
        tracing::warn!(
            "skipping {}:{} ({}) — {error}",
            node.protocol.as_str(),
            node.address,
            node.label.as_deref().unwrap_or("")
        );
    }
    Ok(text)
}

/// Like [`render_all`], but also reports what could not be rendered.
pub fn render_all_checked(nodes: &[Node]) -> Result<(String, Vec<(Node, Error)>)> {
    let mut out = String::new();
    let mut failed = Vec::new();
    for node in nodes {
        match render(node) {
            Ok(link) => {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(&link);
            }
            Err(error) => failed.push((node.clone(), error)),
        }
    }
    Ok((out, failed))
}

/// Parse a newline-separated list of links, skipping blanks and comments.
pub fn parse_list(input: &str) -> Result<Vec<Node>> {
    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match parse(line) {
            Ok(node) => nodes.push(node),
            Err(e) => errors.push(format!("{}: {e}", crate::util::truncate_public(line))),
        }
    }
    if nodes.is_empty() && !errors.is_empty() {
        return Err(Error::MalformedLink(format!(
            "no valid links found ({} errors, first: {})",
            errors.len(),
            errors[0]
        )));
    }
    Ok(nodes)
}

mod anytls;
mod shadowsocks;
mod socks;
mod tuic;
