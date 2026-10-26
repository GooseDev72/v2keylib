//! Filters: dedup, IP/CIDR whitelists & blacklists, protocol/port selectors.

pub mod ip;
pub mod junk;
pub mod stubs;

use std::collections::HashSet;
use std::net::IpAddr;

use crate::error::Result;
use crate::node::{Node, Protocol};

use ip::{IpMatcher, Whitelist};
pub use junk::{clean as clean_junk, strip as strip_junk, JunkFilter};
pub use ip::{DomainSet as Domains, IpSet};
pub use stubs::{clean, clean_with, StubFilter, StubReason};

/// Remove duplicates by `protocol + address + uuid + port + sni + security`.
pub fn dedup(nodes: Vec<Node>) -> Vec<Node> {
    dedup_with(nodes, |n| n.dedup_key())
}

/// Remove duplicates by every parameter that makes a node what it is.
///
/// The stricter cousin of [`dedup`], for a list assembled out of many sources:
/// the same endpoint shows up with a different path, a different transport, a
/// `flow` added or dropped, and those are separate rows in a client's server
/// list that do not behave the same. Names and unknown query params are ignored
/// — see [`Node::strict_key`].
pub fn dedup_strict(nodes: Vec<Node>) -> Vec<Node> {
    dedup_with(nodes, |n| n.strict_key())
}

/// How many entries a given identity drops.
pub fn duplicates(nodes: &[Node], key: impl Fn(&Node) -> String) -> usize {
    let mut seen: HashSet<String> = HashSet::with_capacity(nodes.len());
    let mut dropped = 0;
    for node in nodes {
        if !seen.insert(key(node)) {
            dropped += 1;
        }
    }
    dropped
}

/// The strict identity, named because callers pick it over the loose one.
pub fn strict_key(node: &Node) -> String {
    node.strict_key()
}

/// Deduplicate using a custom identity function.
pub fn dedup_with<F: Fn(&Node) -> String>(nodes: Vec<Node>, key: F) -> Vec<Node> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        if seen.insert(key(&node)) {
            out.push(node);
        }
    }
    out
}

/// Deduplicate only by endpoint (`address:port`), ignoring credentials.
pub fn dedup_by_endpoint(nodes: Vec<Node>) -> Vec<Node> {
    dedup_with(nodes, |n| format!("{}:{}", n.address, n.port))
}

/// Keep only nodes whose address is inside one of the CIDRs / IPs.
pub fn keep_ips(nodes: Vec<Node>, nets: &[IpMatcher]) -> Vec<Node> {
    nodes
        .into_iter()
        .filter(|n| nets.iter().any(|m| m.matches_ip(&n.address)))
        .collect()
}

/// Drop nodes whose address is inside one of the CIDRs / IPs.
pub fn drop_ips(nodes: Vec<Node>, nets: &[IpMatcher]) -> Vec<Node> {
    nodes
        .into_iter()
        .filter(|n| !nets.iter().any(|m| m.matches_ip(&n.address)))
        .collect()
}

/// Keep only nodes matching the whitelist (an empty whitelist keeps nothing,
/// which is the safe interpretation of "allow list").
pub fn apply_whitelist(nodes: Vec<Node>, wl: &Whitelist) -> Result<Vec<Node>> {
    wl.filter(nodes)}

/// Keep nodes with one of the given protocols.
pub fn keep_protocols(nodes: Vec<Node>, protocols: &[Protocol]) -> Vec<Node> {
    nodes
        .into_iter()
        .filter(|n| protocols.contains(&n.protocol))
        .collect()
}

/// Keep nodes whose port is in `ports`.
pub fn keep_ports(nodes: Vec<Node>, ports: &[u16]) -> Vec<Node> {
    nodes.into_iter().filter(|n| ports.contains(&n.port)).collect()
}

/// Drop nodes whose port is in `ports`.
pub fn drop_ports(nodes: Vec<Node>, ports: &[u16]) -> Vec<Node> {
    nodes.into_iter().filter(|n| !ports.contains(&n.port)).collect()
}

/// Keep nodes whose SNI/host matches one of the substrings (case-insensitive).
pub fn keep_by_name(nodes: Vec<Node>, needles: &[String]) -> Vec<Node> {
    nodes
        .into_iter()
        .filter(|n| {
            let hay = format!(
                "{} {} {}",
                n.label.clone().unwrap_or_default(),
                n.sni.clone().unwrap_or_default(),
                n.address
            )
            .to_ascii_lowercase();
            needles.iter().any(|needle| {
                let needle = needle.to_ascii_lowercase();
                !needle.is_empty() && hay.contains(&needle)
            })
        })
        .collect()
}

/// Parse a textual address that may be a CIDR, an IP, or a hostname.
pub fn matcher_from_str(input: &str) -> Result<IpMatcher> {
    IpMatcher::parse(input)
}

/// Resolve node addresses to IPs when possible (best effort, blocking).
pub fn resolved_ips(nodes: &[Node]) -> Vec<(usize, IpAddr)> {
    use std::net::ToSocketAddrs;
    let mut out = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        if let Ok(ip) = node.address.parse::<IpAddr>() {
            out.push((i, ip));
            continue;
        }
        if let Ok(mut addrs) = (node.address.as_str(), node.port).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                out.push((i, addr.ip()));
            }
        }
    }
    out
}
