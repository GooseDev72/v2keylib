//! Geo resolution: local MaxMind DB, remote IP-API, and cascade detection.

pub mod api;
pub mod cascade;
pub mod db;
pub mod mmdb;
pub mod xray_dat;

pub use db::GeoDb;

use std::net::IpAddr;

use crate::error::Result;
use crate::node::Node;

/// Resolver backed by XRay's own `geoip.dat` (protobuf, *not* a MaxMind .mmdb).
///
/// See [`xray_dat`] for the wire layout. Use it when the dataset is the one XRay
/// itself ships (`runetfreedom/russia-v2ray-rules-dat`, `Loyalsoldier/geoip`),
/// because those files also carry category groups such as `RU-BLOCKED`.
pub struct XrayDatResolver {
    pub data: xray_dat::GeoIpDat,
}

impl XrayDatResolver {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            data: xray_dat::GeoIpDat::open(path)?,
        })
    }

    /// XRay datasets mix ISO country codes with category tags (`private`,
    /// `RU-BLOCKED`, `GOOGLE`, `DDOS-GUARD`...). A group name that is not a
    /// two-letter code is a category, not a country.
    pub fn is_category(code: &str) -> bool {
        !(code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()))
    }

    /// Every group name containing `ip`, most specific network first.
    pub fn groups_of(&self, ip: IpAddr) -> Vec<&str> {
        self.data
            .lookup(ip)
            .iter()
            .map(|g| g.code.as_str())
            .collect()
    }
}

impl XrayDatResolver {
    /// Countries only: a category tag is never returned as a country, so
    /// `192.168.1.1` is "unknown country", not "PRIVATE".
    pub fn country_of(&self, ip: IpAddr) -> Option<String> {
        self.data
            .lookup(ip)
            .into_iter()
            .map(|g| g.code.clone())
            .find(|code| !XrayDatResolver::is_category(code))
    }
}

impl GeoResolver for XrayDatResolver {
    fn country_of(&self, ip: IpAddr) -> Option<String> {
        XrayDatResolver::country_of(self, ip)
    }

    fn resolve_ip(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        let hits = self.data.lookup(ip);
        if hits.is_empty() {
            return Ok(None);
        }
        // Prefer a real country code over a category group.
        let chosen = hits
            .iter()
            .find(|g| !XrayDatResolver::is_category(&g.code))
            .copied()
            .unwrap_or_else(|| hits[0]);
        Ok(Some(GeoInfo {
            ip,
            country: (!XrayDatResolver::is_category(&chosen.code)).then(|| chosen.code.clone()),
            city: None,
            anycast: false,
        }))
    }
}

/// Country of an address, normalized to ISO-3166 alpha-2 where possible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeoInfo {
    pub ip: IpAddr,
    /// ISO code, or the raw GeoIP name when it cannot be mapped.
    pub country: Option<String>,
    pub city: Option<String>,
    /// True when the address is an anycast/CDN exit rather than a real endpoint.
    pub anycast: bool,
}

impl GeoInfo {
    pub fn unknown(ip: IpAddr) -> Self {
        Self {
            ip,
            country: None,
            city: None,
            anycast: false,
        }
    }
}

/// Anything that can resolve a country for an IP.
///
/// Resolvers must be `Send + Sync`: the pipeline is async and may be shared.
pub trait GeoResolver: Send + Sync {
    fn resolve_ip(&self, ip: IpAddr) -> Result<Option<GeoInfo>>;
    fn country_of(&self, ip: IpAddr) -> Option<String> {
        self.resolve_ip(ip).ok().flatten().and_then(|g| g.country)
    }
}

/// A resolver that knows nothing.
pub struct NullResolver;

impl GeoResolver for NullResolver {
    fn resolve_ip(&self, _ip: IpAddr) -> Result<Option<GeoInfo>> {
        Ok(None)
    }
}

/// How a node relates to the machine running the scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cascade {
    /// Entry country == exit country.
    Direct,
    /// Entry country differs from exit country.
    Cross,
    /// Exit country unknown, cannot tell.
    Unknown,
}

/// Classify the node's exit country against the local (entry) country.
pub fn cascade_kind(entry: Option<&str>, exit: Option<&str>) -> Cascade {
    match (entry, exit) {
        (Some(a), Some(b)) => {
            if a.eq_ignore_ascii_case(b) {
                Cascade::Direct
            } else {
                Cascade::Cross
            }
        }
        _ => Cascade::Unknown,
    }
}

/// The entry country for a known public IP, from a local database.
///
/// The entry side must be resolved from *your own public address*: a local
/// MaxMind/geoip database has no record for a loopback address, so asking it
/// about 127.0.0.1 always yields nothing (or `PRIVATE`).
///
/// ```no_run
/// use v2keylib::geo::{self, XrayDatResolver};
///
/// let db = XrayDatResolver::open("geoip.dat")?;
/// let entry = geo::entry_country_for("91.238.88.17".parse().unwrap(), &db);
/// # let _ = entry;
/// # Ok::<(), v2keylib::Error>(())
/// ```
pub fn entry_country_for(ip: IpAddr, resolver: &dyn GeoResolver) -> Option<String> {
    resolver.country_of(ip)
}

/// Cascade for one node, given the entry country and the node's exit country.
pub fn cascade_for(entry: Option<&str>, exit: Option<&str>) -> Cascade {
    cascade_kind(entry, exit)
}

/// Annotate every node with its exit country in `node.extra["country"]` and
/// return the per-node cascade classification.
pub fn annotate(
    nodes: &mut [Node],
    resolver: &dyn GeoResolver,
    entry: Option<&str>,
) -> Vec<Cascade> {
    nodes
        .iter_mut()
        .map(|node| {
            let exit = match node.address.parse::<IpAddr>() {
                Ok(ip) => {
                    let country = resolver.country_of(ip);
                    let anycast = resolver
                        .resolve_ip(ip)
                        .ok()
                        .flatten()
                        .map(|i| i.anycast)
                        .unwrap_or(false);
                    node.extra.insert(
                        "country".into(),
                        country.clone().unwrap_or_else(|| "??".into()),
                    );
                    if anycast {
                        node.extra.insert("anycast".into(), "1".into());
                    }
                    country
                }
                Err(_) => {
                    node.extra
                        .insert("country".into(), "hostname".into());
                    None
                }
            };
            cascade_kind(entry, exit.as_deref())
        })
        .collect()
}

/// Annotate nodes using a remote IP-API resolver (async, cached per IP).
pub async fn annotate_api(
    nodes: &mut [Node],
    resolver: &api::IpApiResolver,
    entry: Option<&str>,
    concurrency: usize,
) -> Vec<Cascade> {
    let ips: Vec<IpAddr> = nodes
        .iter()
        .filter_map(|n| n.address.parse::<IpAddr>().ok())
        .collect();
    let resolved = resolver.lookup_many(&ips, concurrency).await;
    let table: std::collections::HashMap<IpAddr, GeoInfo> = resolved
        .into_iter()
        .filter_map(|(ip, info)| info.map(|i| (ip, i)))
        .collect();

    nodes
        .iter_mut()
        .map(|node| {
            let exit = match node.address.parse::<IpAddr>() {
                Ok(ip) => match table.get(&ip) {
                    Some(info) => {
                        node.extra.insert(
                            "country".into(),
                            info.country.clone().unwrap_or_else(|| "??".into()),
                        );
                        if let Some(city) = &info.city {
                            node.extra.insert("city".into(), city.clone());
                        }
                        if info.anycast {
                            node.extra.insert("anycast".into(), "1".into());
                        }
                        info.country.clone()
                    }
                    None => {
                        node.extra.insert("country".into(), "??".into());
                        None
                    }
                },
                Err(_) => {
                    node.extra
                        .insert("country".into(), "hostname".into());
                    None
                }
            };
            cascade_kind(entry, exit.as_deref())
        })
        .collect()
}

/// Keep nodes whose exit country is in the list (`DE`, `de`, `Germany` all work).
pub fn filter_by_country(nodes: Vec<Node>, countries: &[String]) -> Vec<Node> {
    if countries.is_empty() {
        return nodes;
    }
    let wanted: Vec<String> = countries.iter().map(|c| c.trim().to_ascii_uppercase()).collect();
    nodes
        .into_iter()
        .filter(|n| {
            n.extra
                .get("country")
                .map(|c| wanted.contains(&c.to_ascii_uppercase()))
                .unwrap_or(false)
        })
        .collect()
}
