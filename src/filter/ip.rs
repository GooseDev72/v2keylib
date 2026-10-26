//! IP / CIDR matching helpers.

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

use crate::error::{Error, Result};
use crate::node::Node;

/// A single IP or CIDR rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpMatcher {
    Ip(IpAddr),
    Net(IpNet),
}

impl IpMatcher {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(Error::InvalidValue {
                field: "cidr".into(),
                value: input.into(),
            });
        }
        if let Ok(ip) = IpAddr::from_str(input) {
            return Ok(IpMatcher::Ip(ip));
        }
        IpNet::from_str(input)
            .map(IpMatcher::Net)
            .map_err(|_| Error::InvalidValue {
                field: "cidr".into(),
                value: input.into(),
            })
    }

    /// Does the matcher cover `ip`?
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            IpMatcher::Ip(a) => a == ip,
            IpMatcher::Net(net) => net.contains(ip),
        }
    }

    /// Match a textual address; hostnames only match if literally equal.
    pub fn matches_ip(&self, address: &str) -> bool {
        match self.parse_ip(address) {
            Some(ip) => self.matches(&ip),
            None => false,
        }
    }

    pub fn parse_ip(&self, address: &str) -> Option<IpAddr> {
        IpAddr::from_str(address.trim()).ok()
    }

    pub fn is_private_network(&self) -> bool {
        match self {
            IpMatcher::Ip(ip) => is_private(*ip),
            IpMatcher::Net(net) => is_private(net.network()),
        }
    }
}

impl FromStr for IpMatcher {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        IpMatcher::parse(s)
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Allow list with optional "keep LAN nodes too" escape hatch.
#[derive(Clone, Debug, Default)]
pub struct Whitelist {
    pub entries: Vec<IpMatcher>,
    /// Keep nodes that resolve to private/reserved addresses (LAN servers).
    pub allow_private: bool,
    /// Treat an empty allow list as "allow everything".
    pub allow_empty: bool,
}

impl Whitelist {
    pub fn parse_list(input: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for line in input.lines() {
            // strip `#` comments, both whole-line and trailing
            let line = match line.split_once('#') {
                Some((head, _)) => head,
                None => line,
            };
            for token in line.split([' ', ',', '\t', ';']) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                entries.push(IpMatcher::parse(token)?);
            }
        }
        Ok(Self {
            entries,
            allow_private: false,
            allow_empty: false,
        })
    }

    pub fn parse_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse_list(&text)
    }

    pub fn with_allow_private(mut self, allow: bool) -> Self {
        self.allow_private = allow;
        self
    }

    pub fn allow_all() -> Self {
        Self {
            entries: Vec::new(),
            allow_private: true,
            allow_empty: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Keep nodes matching the allow list. Without DNS resolution this only
    /// matches nodes whose address is literally an IP inside a listed network;
    /// call [`crate::filter::resolved_ips`] first if hostnames must be matched.
    pub fn filter(&self, nodes: Vec<Node>) -> Result<Vec<Node>> {
        if self.entries.is_empty() {
            return if self.allow_empty || self.allow_private {
                Ok(nodes)
            } else {
                Err(Error::InvalidValue {
                    field: "whitelist".into(),
                    value: "empty allow list".into(),
                })
            };
        }
        Ok(nodes
            .into_iter()
            .filter(|n| {
                if self.allow_private
                    && n.address.parse::<IpAddr>().map(is_private).unwrap_or(false)
                {
                    return true;
                }
                self.entries.iter().any(|m| m.matches_ip(&n.address))
            })
            .collect())
    }
}

/// A list of domain names, matched by suffix on label boundaries.
///
/// A plain `contains` would be wrong in a way that matters here: `avito.ru`
/// must not match `notavito.ru`. So a host matches an entry when the two are
/// equal, or when the host ends with `.` followed by the entry — the same shape
/// as a cookie domain, and the shape a public suffix list would give.
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    entries: Vec<String>,
}

impl DomainSet {
    /// One domain or suffix per line; `#` starts a comment.
    pub fn parse_list(input: &str) -> Self {
        let entries = input
            .lines()
            .map(|line| match line.split_once('#') {
                Some((head, _)) => head,
                None => line,
            })
            .flat_map(|line| line.split([' ', '\t', ',', ';']))
            .map(|t| t.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        Self { entries }
    }

    pub fn parse_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse_list(&text))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Does `host` equal, or sit under, one of the entries?
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return false;
        }
        self.entries.iter().any(|entry| {
            host == *entry
                || (host.len() > entry.len() && host.ends_with(entry.as_str()) && {
                    // the character before the suffix must be the label dot
                    let cut = host.len() - entry.len();
                    cut > 0 && host.as_bytes()[cut - 1] == b'.'
                })
        })
    }
}

/// A membership set over IPs and CIDR networks.
///
/// [`Whitelist`] answers the same question by walking a list, which is fine for
/// the CIDRs a person types and not fine for the 125 000 addresses a published
/// list holds: that is 125 000 comparisons per node. This keeps single
/// addresses in a hash set and only walks the networks, so a list like that
/// costs one lookup.
#[derive(Clone, Debug, Default)]
pub struct IpSet {
    ips: std::collections::HashSet<IpAddr>,
    nets: Vec<IpNet>,
    /// Lines that were neither an IP nor a CIDR, kept so a caller can say so.
    bad: usize,
}

impl IpSet {
    pub fn parse_list(input: &str) -> Self {
        let mut set = Self::default();
        for line in input.lines() {
            let line = match line.split_once('#') {
                Some((head, _)) => head,
                None => line,
            };
            for token in line.split([' ', ',', '\t', ';']) {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }
                if let Ok(ip) = IpAddr::from_str(token) {
                    set.ips.insert(ip);
                } else if let Ok(net) = IpNet::from_str(token) {
                    set.nets.push(net);
                } else {
                    set.bad += 1;
                }
            }
        }
        set
    }

    pub fn parse_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse_list(&text))
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.nets.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ips.len() + self.nets.len()
    }

    pub fn bad_lines(&self) -> usize {
        self.bad
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ips.contains(ip) || self.nets.iter().any(|net| net.contains(ip))
    }

    /// Membership by text. A hostname is not in the set by name — resolve it
    /// first, or it will silently read as "not listed".
    pub fn contains_ip(&self, address: &str) -> bool {
        match IpAddr::from_str(address.trim()) {
            Ok(ip) => self.contains(&ip),
            Err(_) => false,
        }
    }
}
