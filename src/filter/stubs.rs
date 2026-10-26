//! Dropping placeholder ("stub") entries from a subscription.
//!
//! Free-subscription providers pad their output with entries that are not real
//! servers: unroutable addresses, loopback, DNS resolvers used as decoys, or
//! outbounds with no address at all. Left in place they survive every dedup and
//! end up as first-class members of a balancer, where they only add latency and
//! failed handshakes.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::node::Node;

/// Addresses that are stubs unless the user explicitly asks to keep them.
pub const DEFAULT_STUB_ADDRESSES: &[&str] = &[
    "0.0.0.0",
    "::",
    "127.0.0.1",
    "::1",
    "localhost",
    "1.1.1.1",     // Cloudflare DNS, classic decoy
    "8.8.8.8",     // Google DNS, classic decoy
    "1.0.0.1",     // APNIC/Cloudflare special
    "208.67.222.222",
    "208.67.220.220",
    "9.9.9.9",
    "149.112.112.112",
    "100.100.100.200", // Alibaba metadata
    "169.254.169.254", // cloud instance metadata (AWS/GCP)
];

/// Why an entry was considered a stub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StubReason {
    /// Address is on the stub list.
    Address,
    /// Unroutable / loopback / link-local / metadata address.
    Special,
    /// No port, or port 0.
    NoPort,
    /// No host at all, or no credentials.
    Empty,
}

/// A stub verdict plus the reason, for reporting.
#[derive(Clone, Debug)]
pub struct Stub {
    pub node: Node,
    pub reason: StubReason,
}

/// Configuration for stub detection.
#[derive(Clone, Debug)]
pub struct StubFilter {
    pub addresses: HashSet<String>,
    /// Drop any address in a non-routable range even if it is not on the list.
    pub drop_special_ranges: bool,
    /// Drop entries with no port.
    pub require_port: bool,
    /// Drop vless/vmess nodes with an empty uuid, trojan with an empty password.
    pub require_credentials: bool,
}

impl Default for StubFilter {
    fn default() -> Self {
        Self {
            addresses: DEFAULT_STUB_ADDRESSES
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            drop_special_ranges: true,
            require_port: true,
            require_credentials: true,
        }
    }
}

impl StubFilter {
    pub fn with_addresses<I, S>(mut self, addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.addresses = addresses
            .into_iter()
            .map(|s| s.as_ref().trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        self
    }

    pub fn keeping_special_ranges(mut self, keep: bool) -> Self {
        self.drop_special_ranges = !keep;
        self
    }

    pub fn is_stub(&self, node: &Node) -> Option<StubReason> {
        let address = node.address.trim();
        if address.is_empty() {
            return Some(StubReason::Empty);
        }
        if self.addresses.contains(&address.to_ascii_lowercase()) {
            return Some(StubReason::Address);
        }
        if self.drop_special_ranges && is_special(address) {
            return Some(StubReason::Special);
        }
        if self.require_port && node.port == 0 {
            return Some(StubReason::NoPort);
        }
        if self.require_credentials && !has_credentials(node) {
            return Some(StubReason::Empty);
        }
        None
    }
}

/// Non-routable, loopback, link-local and instance-metadata addresses.
pub fn is_special(address: &str) -> bool {
    let Ok(ip) = address.parse::<IpAddr>() else {
        return address.eq_ignore_ascii_case("localhost")
            || address.ends_with(".localhost")
            || address.ends_with(".local")
            || address.ends_with(".internal");
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                // 100.64/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 169.254/16 link-local, includes cloud metadata 169.254.169.254
                || v4.is_link_local()
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                // 198.18/15 benchmarking
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240/4 reserved
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // ff00::/8 multicast
                || (v6.segments()[0] & 0xff00) == 0xff00
        }
    }
}

fn has_credentials(node: &Node) -> bool {
    match node.protocol {
        crate::node::Protocol::Vless | crate::node::Protocol::Vmess => node
            .uuid
            .as_deref()
            .map(|u| !u.trim().is_empty())
            .unwrap_or(false),
        crate::node::Protocol::Trojan => node
            .password
            .as_deref()
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false),
        _ => true,
    }
}

/// Split nodes into (kept, removed).
pub fn partition(nodes: Vec<Node>, filter: &StubFilter) -> (Vec<Node>, Vec<Stub>) {
    let mut kept = Vec::with_capacity(nodes.len());
    let mut removed = Vec::new();
    for node in nodes {
        match filter.is_stub(&node) {
            Some(reason) => removed.push(Stub { node, reason }),
            None => kept.push(node),
        }
    }
    (kept, removed)
}

/// Remove stubs, returning only the survivors.
pub fn clean(nodes: Vec<Node>) -> Vec<Node> {
    clean_with(nodes, &StubFilter::default())
}

pub fn clean_with(nodes: Vec<Node>, filter: &StubFilter) -> Vec<Node> {
    partition(nodes, filter).0
}
