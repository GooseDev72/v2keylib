//! MaxMind GeoLite2/GeoIP2 database reader.

use std::net::IpAddr;
use std::path::Path;

use maxminddb::geoip2;

use crate::error::{Error, Result};
use crate::geo::{GeoInfo, GeoResolver};

/// Country DB (GeoLite2-Country / GeoIP2-Country).
pub struct CountryDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl CountryDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path.as_ref())
            .map_err(|e| Error::GeoIp(e.to_string()))?;
        Ok(Self { reader })
    }

    /// Resolve, preferring the city DB's country record when present.
    ///
    /// `maxminddb` reports a wrong-type lookup as an error, so a country DB
    /// simply misses here and the ASN record is tried instead.
    fn lookup(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        if let Ok(rec) = self.reader.lookup::<geoip2::City>(ip) {
            return Ok(Some(GeoInfo {
                ip,
                country: rec.country.and_then(|c| c.iso_code).map(str::to_string),
                city: rec
                    .city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").map(|s| s.to_string())),
                anycast: false,
            }));
        }
        if let Ok(rec) = self.reader.lookup::<geoip2::Country>(ip) {
            return Ok(Some(GeoInfo {
                ip,
                country: rec.country.and_then(|c| c.iso_code).map(str::to_string),
                city: None,
                anycast: false,
            }));
        }
        // ASN / anonymous databases have no country; still report "unknown".
        Ok(Some(GeoInfo::unknown(ip)))
    }
}

impl GeoResolver for CountryDb {
    fn resolve_ip(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        self.lookup(ip)
    }
}

/// In-memory resolver over an IP -> country table (e.g. parsed from an API
/// response or a private list).
#[derive(Default)]
pub struct TableResolver {
    entries: std::collections::HashMap<IpAddr, String>,
}

impl TableResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, ip: IpAddr, country: impl Into<String>) {
        self.entries.insert(ip, country.into());
    }

    /// Parse lines of `<ip> <country>`.
    pub fn parse_list(text: &str) -> Result<Self> {
        let mut r = Self::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(ip), Some(country)) = (parts.next(), parts.next()) else {
                continue;
            };
            let ip: IpAddr = ip
                .parse()
                .map_err(|_| Error::GeoIp(format!("bad ip: {ip}")))?;
            r.insert(ip, country.to_string());
        }
        Ok(r)
    }
}

impl GeoResolver for TableResolver {
    fn resolve_ip(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        Ok(self.entries.get(&ip).map(|c| GeoInfo {
            ip,
            country: Some(c.clone()),
            city: None,
            anycast: false,
        }))
    }
}
