//! Cascade detection for a whole config.
//!
//! "Cascade" is the relation between the country you connect *from* (entry) and
//! the country the tunnel *exits* in:
//!
//! ```text
//! entry RU  >  exit LV     Cross    ("каскад" — трафик уходит за границу)
//! entry RU  >  exit RU      Direct
//! entry RU  >  exit ??      Unknown  (страна не определилась)
//! ```
//!
//! The two sides use different data on purpose: the entry side is one IP (your
//! own), so a remote API is acceptable and a local database is instant; the
//! exit side is thousands of IPs, so a local database is the practical choice
//! and the API is a fallback.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::error::Result;
use crate::geo::api::IpApiResolver;
use crate::geo::{Cascade, GeoResolver};
use crate::node::Node;

/// What is known about one node's exit.
#[derive(Clone, Debug)]
pub struct NodeCascade {
    /// Position in the input list.
    pub index: usize,
    /// `host:port` as written, which is what a config entry refers to.
    pub address: String,
    /// The node's own name from the subscription, if it carries one.
    ///
    /// Worth keeping next to the resolved country: free subscriptions often
    /// label a node with a country it does not actually exit from.
    pub label: Option<String>,
    /// Countries the label itself claims, in order.
    ///
    /// A label like `🇷🇺➜🇵🇱` states a chain; [`NodeCascade::claimed_exit`] is
    /// what it says the connection finally leaves from, which is the claim to
    /// compare against `country`.
    pub claimed_route: Vec<String>,
    /// IP the address resolved to, when known.
    pub ip: Option<IpAddr>,
    pub country: Option<String>,
    pub city: Option<String>,
    /// True when the dataset flagged the address as anycast/CDN.
    pub anycast: bool,
    pub cascade: Cascade,
}

impl NodeCascade {
    /// `lv.example:443 (LV) Cross`
    pub fn describe(&self) -> String {
        let host = match (&self.label, &self.ip) {
            (Some(label), Some(ip)) => format!("{label} ({ip})"),
            (Some(label), None) => label.clone(),
            (None, Some(ip)) => ip.to_string(),
            (None, None) => "(unknown)".to_string(),
        };
        format!(
            "{host} [{}] {:?}",
            self.country.as_deref().unwrap_or("??"),
            self.cascade
        )
    }

    /// The country the label claims the connection finally leaves from.
    pub fn claimed_exit(&self) -> Option<&str> {
        self.claimed_route.last().map(String::as_str)
    }

    /// `RU -> PL`, or nothing when the label names no country.
    pub fn claimed_chain(&self) -> Option<String> {
        if self.claimed_route.is_empty() {
            return None;
        }
        Some(self.claimed_route.join(" -> "))
    }

    /// True when the label names a country and it is not where the node exits.
    ///
    /// The point of comparing the two: a whitelist built from the names in a
    /// free subscription does not select the nodes it appears to.
    pub fn label_contradicts_geodata(&self) -> bool {
        match (self.claimed_exit(), self.country.as_deref()) {
            (Some(claimed), Some(actual)) => claimed != actual,
            _ => false,
        }
    }
}

/// One `entry -> exit` row of the cascade table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub entry: String,
    pub exit: String,
    pub count: usize,
}

impl Route {
    /// `RU -> GB`
    pub fn describe(&self) -> String {
        format!("{} -> {}", self.entry, self.exit)
    }
}

/// Cascade for an entire config.
#[derive(Clone, Debug)]
pub struct CascadeReport {
    pub entry_ip: Option<IpAddr>,
    pub entry_country: Option<String>,
    pub nodes: Vec<NodeCascade>,
    /// Counts per classification, ready for a summary line.
    pub summary: BTreeMap<&'static str, usize>,
    /// Nodes whose address could not be resolved to an IP at all.
    pub unresolved: usize,
    /// Nodes whose country could not be determined.
    pub unknown_country: usize,
}

impl CascadeReport {
    /// Share of nodes that actually leave the entry country, 0.0..=1.0.
    pub fn cross_share(&self) -> f64 {
        let known = self.summary.get("Cross").copied().unwrap_or(0)
            + self.summary.get("Direct").copied().unwrap_or(0);
        if known == 0 {
            return 0.0;
        }
        self.summary.get("Cross").copied().unwrap_or(0) as f64 / known as f64
    }

    /// Node counts per entry -> exit country pair, ordered by the count.
    ///
    /// This is the whole cascade in one table: which countries a run from
    /// `entry` can actually reach, and how many nodes get there.
    pub fn routes(&self) -> Vec<Route> {
        let entry = self.entry_country.as_deref().unwrap_or("??").to_string();
        let mut counts: BTreeMap<String, (String, usize)> = BTreeMap::new();
        for node in &self.nodes {
            let exit = node.country.clone().unwrap_or_else(|| "??".into());
            let slot = counts.entry(exit).or_insert_with(|| (entry.clone(), 0));
            slot.1 += 1;
        }
        let mut routes: Vec<Route> = counts
            .into_iter()
            .map(|(exit, (entry, count))| Route { entry, exit, count })
            .collect();
        routes.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.exit.cmp(&b.exit)));
        routes
    }

    /// The pair most nodes fall into, as `RU -> GB`.
    pub fn verdict(&self) -> String {
        match self.routes().first() {
            Some(route) => route.describe(),
            None => "no nodes".to_string(),
        }
    }

    pub fn summary_line(&self) -> String {
        format!(
            "entry {} ({}) | direct {} | cross {} | unknown {} | unresolved {}",
            self.entry_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "?".into()),
            self.entry_country.as_deref().unwrap_or("??"),
            self.summary.get("Direct").copied().unwrap_or(0),
            self.summary.get("Cross").copied().unwrap_or(0),
            self.summary.get("Unknown").copied().unwrap_or(0),
            self.unresolved,
        )
    }
}

/// Resolve hostname addresses in place, storing the IP in `extra["ip"]`.
///
/// A cascade report is only as good as the addresses it can look up, and real
/// subscriptions are full of hostnames that local databases cannot resolve.
/// Returns how many nodes were left unresolved.
pub async fn resolve_addresses(nodes: &mut [Node], concurrency: usize) -> usize {
    use futures::StreamExt;

    // only hostnames need work
    let pending: Vec<usize> = nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.address.parse::<IpAddr>().is_err())
        .map(|(i, _)| i)
        .collect();
    if pending.is_empty() {
        return 0;
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let resolved: Vec<(usize, Option<IpAddr>)> = futures::stream::iter(
        pending.iter().map(|&i| {
            let semaphore = semaphore.clone();
            let host = nodes[i].address.clone();
            async move {
                let _permit = semaphore.acquire_owned().await.ok();
                let ip = tokio::net::lookup_host((host.as_str(), 0u16))
                    .await
                    .ok()
                    .and_then(|mut addrs| addrs.next().map(|a| a.ip()));
                (i, ip)
            }
        }),
    )
    .buffer_unordered(concurrency.max(1))
    .collect()
    .await;

    let mut failed = 0;
    for (i, ip) in resolved {
        match ip {
            Some(ip) => {
                nodes[i].extra.insert("ip".into(), ip.to_string());
            }
            None => failed += 1,
        }
    }
    failed
}

/// Classify a node list against a local resolver.
///
/// Synchronous and offline: only addresses that are already IPs (either written
/// as literals or filled in by [`resolve_addresses`]) can be classified.
pub fn cascade_report(
    nodes: &[Node],
    exit: &dyn GeoResolver,
    entry_country: Option<&str>,
) -> CascadeReport {
    let mut rows = Vec::with_capacity(nodes.len());
    let mut summary: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unresolved = 0;
    let mut unknown_country = 0;

    for (index, node) in nodes.iter().enumerate() {
        let ip = node_ip(node);
        let info = ip.and_then(|ip| exit.resolve_ip(ip).ok().flatten());
        let country = info.as_ref().and_then(|i| i.country.clone());
        let cascade = cascade_for_node(entry_country, country.as_deref());
        match cascade {
            Cascade::Direct => *summary.entry("Direct").or_default() += 1,
            Cascade::Cross => *summary.entry("Cross").or_default() += 1,
            Cascade::Unknown => {
                *summary.entry("Unknown").or_default() += 1;
                if ip.is_some() {
                    unknown_country += 1;
                }
            }
        }
        if ip.is_none() {
            unresolved += 1;
        }
        rows.push(NodeCascade {
            index,
            address: node.socket_addr(),
            label: node.label.clone(),
            claimed_route: node.claimed_route(),
            ip,
            country,
            city: info.as_ref().and_then(|i| i.city.clone()),
            anycast: info.map(|i| i.anycast).unwrap_or(false),
            cascade,
        });
    }

    CascadeReport {
        entry_ip: None,
        entry_country: entry_country.map(str::to_string),
        nodes: rows,
        summary,
        unresolved,
        unknown_country,
    }
}

/// The IP a node should be looked up by: an explicit `extra["ip"]` wins over the
/// address, so a hostname resolved earlier is still usable.
pub fn node_ip(node: &Node) -> Option<IpAddr> {
    node.extra
        .get("ip")
        .and_then(|raw| raw.parse().ok())
        .or_else(|| node.address.parse().ok())
}

fn cascade_for_node(entry: Option<&str>, exit: Option<&str>) -> Cascade {
    // An unknown exit is never "direct": no data is not agreement.
    if entry.is_none() || exit.is_none() {
        return Cascade::Unknown;
    }
    crate::geo::cascade_kind(entry, exit)
}

/// Parse a config of any supported shape and classify it, all offline.
///
/// Accepts `vless://` lists, base64 subscriptions, XRay JSON (including a JSON
/// array of configs), sing-box JSON and mihomo YAML. Hostnames are left
/// unresolved; call [`resolve_addresses`] first to fill them in.
pub fn cascade_from_config(
    body: &str,
    exit: &dyn GeoResolver,
    entry_country: Option<&str>,
) -> Result<CascadeReport> {
    let nodes = crate::subscription::parse_body(body)?.nodes();
    Ok(cascade_report(&nodes, exit, entry_country))
}

/// Same, but with a remote resolver for the exit side and DNS for hostnames.
///
/// This is the version to use when the addresses are hostnames or the local
/// database has no record of them; it makes one HTTP request per distinct IP.
pub async fn cascade_from_config_api(
    body: &str,
    api: &IpApiResolver,
    entry_country: Option<&str>,
    concurrency: usize,
) -> Result<CascadeReport> {
    let mut nodes = crate::subscription::parse_body(body)?.nodes();
    resolve_addresses(&mut nodes, concurrency).await;

    let ips: Vec<IpAddr> = nodes.iter().filter_map(node_ip).collect();
    let resolved = api.lookup_many(&ips, concurrency).await;
    let table: BTreeMap<IpAddr, crate::geo::GeoInfo> =
        resolved.into_iter().filter_map(|(ip, i)| i.map(|i| (ip, i))).collect();

    let mut rows = Vec::with_capacity(nodes.len());
    let mut summary: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut unresolved = 0;
    let mut unknown_country = 0;

    for (index, node) in nodes.iter().enumerate() {
        let ip = node_ip(node);
        let info = ip.and_then(|ip| table.get(&ip).cloned());
        let country = info.as_ref().and_then(|i| i.country.clone());
        let cascade = cascade_for_node(entry_country, country.as_deref());
        match cascade {
            Cascade::Direct => *summary.entry("Direct").or_default() += 1,
            Cascade::Cross => *summary.entry("Cross").or_default() += 1,
            Cascade::Unknown => {
                *summary.entry("Unknown").or_default() += 1;
                if ip.is_some() {
                    unknown_country += 1;
                }
            }
        }
        if ip.is_none() {
            unresolved += 1;
        }
        rows.push(NodeCascade {
            index,
            address: node.socket_addr(),
            label: node.label.clone(),
            claimed_route: node.claimed_route(),
            ip,
            country,
            city: info.as_ref().and_then(|i| i.city.clone()),
            anycast: info.map(|i| i.anycast).unwrap_or(false),
            cascade,
        });
    }

    Ok(CascadeReport {
        entry_ip: None,
        entry_country: entry_country.map(str::to_string),
        nodes: rows,
        summary,
        unresolved,
        unknown_country,
    })
}

/// Detect the entry country from the machine's public address using a local
/// database.
pub fn entry_from_ip(body_ip: IpAddr, resolver: &dyn GeoResolver) -> Option<String> {
    crate::geo::entry_country_for(body_ip, resolver)
}