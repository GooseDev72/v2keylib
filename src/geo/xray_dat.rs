//! Minimal protobuf wire-format reader, just enough for XRay's `geoip.dat`.
//!
//! XRay's GeoIP data file is **not** a MaxMind `.mmdb`. It is a protobuf message
//! (verified against `transport/internet/splithttp`-era `infra/conf` and the
//! `app/router` geoip definitions):
//!
//! ```proto
//! message CIDR { bytes ip = 1; uint32 prefix = 2; }
//! message GeoIP { string code = 1; repeated CIDR cidr = 2; }
//! message GeoIPList { repeated GeoIP geoip = 1; }
//! ```
//!
//! `code` is normally an ISO-3166 alpha-2 code, but datasets also carry
//! categories such as `private`, `RU-BLOCKED` or `DDOS-GUARD`, so it is treated
//! as an opaque group name here.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A single network from a GeoIP group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Net {
    /// Does this network contain `ip`?
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(target)) => prefix_eq(&net.octets(), &target.octets(), self.prefix),
            (IpAddr::V6(net), IpAddr::V6(target)) => prefix_eq(&net.octets(), &target.octets(), self.prefix),
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rest = prefix % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rest);
    (a[full] & mask) == (b[full] & mask)
}

/// A named group of networks (a country code or a special category).
#[derive(Clone, Debug, Default)]
pub struct Group {
    pub code: String,
    pub nets: Vec<Net>,
}

impl Group {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }
}

/// A parsed `geoip.dat`.
#[derive(Clone, Debug, Default)]
pub struct GeoIpDat {
    pub groups: Vec<Group>,
}

impl GeoIpDat {
    pub fn parse(data: &[u8]) -> Result<Self, crate::error::Error> {
        let mut groups = Vec::new();
        for record in Records::new(data) {
            // top level: repeated GeoIP geoip = 1
            if record.field != 1 {
                continue;
            }
            let Some(body) = record.bytes else { continue };
            let mut group = Group::default();
            for inner in Records::new(body) {
                match (inner.field, inner.bytes) {
                    (1, Some(code)) => group.code = String::from_utf8_lossy(code).to_string(),
                    (2, Some(cidr)) => {
                        if let Some(net) = parse_cidr(cidr) {
                            group.nets.push(net);
                        }
                    }
                    _ => {}
                }
            }
            groups.push(group);
        }
        if groups.is_empty() {
            return Err(crate::error::Error::GeoIp(
                "no geoip groups found — is this really an XRay geoip.dat?".into(),
            ));
        }
        Ok(Self { groups })
    }

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, crate::error::Error> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(&data)
    }

    pub fn group(&self, code: &str) -> Option<&Group> {
        self.groups
            .iter()
            .find(|g| g.code.eq_ignore_ascii_case(code))
    }

    /// Every group that contains `ip`, most specific network first.
    ///
    /// XRay matches routing rules by group name, so returning *all* matches
    /// lets callers ask "is this IP blocked?" and "which country is it?"
    /// from the same file.
    pub fn lookup(&self, ip: IpAddr) -> Vec<&Group> {
        let mut hits: Vec<(&Group, u8)> = self
            .groups
            .iter()
            .filter_map(|g| {
                g.nets
                    .iter()
                    .filter(|n| n.contains(&ip))
                    .map(|n| (g, n.prefix))
                    .max_by_key(|(_, p)| *p)
            })
            .collect();
        // Most specific first: a /32 entry beats a broad /8 country block.
        hits.sort_by_key(|(_, prefix)| std::cmp::Reverse(*prefix));
        hits.into_iter().map(|(g, _)| g).collect()
    }

    pub fn total_nets(&self) -> usize {
        self.groups.iter().map(|g| g.nets.len()).sum()
    }
}

/// A geoip.dat group name is a country code only when it is two letters;
/// everything else (`private`, `RU-BLOCKED`, `GOOGLE`, ...) is a category.
pub fn is_category(code: &str) -> bool {
    !(code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()))
}

impl crate::geo::GeoResolver for GeoIpDat {
    fn resolve_ip(&self, ip: IpAddr) -> crate::error::Result<Option<crate::geo::GeoInfo>> {
        let hits = self.lookup(ip);
        // a real country beats a category; a category alone is not a country
        let chosen = hits
            .iter()
            .find(|g| !is_category(&g.code))
            .copied()
            .or_else(|| hits.first().copied());
        Ok(chosen.map(|g| crate::geo::GeoInfo {
            ip,
            country: (!is_category(&g.code)).then(|| g.code.clone()),
            city: None,
            anycast: false,
        }))
    }
}

fn parse_cidr(buf: &[u8]) -> Option<Net> {
    let mut ip_bytes: Option<&[u8]> = None;
    let mut prefix: u64 = 0;
    for record in Records::new(buf) {
        match record.field {
            1 => ip_bytes = record.bytes,
            2 => prefix = record.varint.unwrap_or(0),
            _ => {}
        }
    }
    let bytes = ip_bytes?;
    let (ip, max) = match bytes.len() {
        4 => (
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
            32u8,
        ),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            (IpAddr::V6(Ipv6Addr::from(octets)), 128u8)
        }
        // truncated or non-canonical encoding; skip rather than guess
        _ => return None,
    };
    if prefix > max as u64 {
        return None;
    }
    Some(Net {
        ip,
        prefix: prefix as u8,
    })
}

/// One decoded protobuf field.
pub struct Record<'a> {
    pub field: u32,
    pub wire: u8,
    pub bytes: Option<&'a [u8]>,
    pub varint: Option<u64>,
}

struct Records<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Records<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let key = read_varint(self.buf, &mut self.pos)?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x7) as u8;
        let mut record = Record {
            field,
            wire,
            bytes: None,
            varint: None,
        };
        match wire {
            0 => record.varint = read_varint(self.buf, &mut self.pos),
            1 => {
                let end = (self.pos + 8).min(self.buf.len());
                record.bytes = Some(&self.buf[self.pos..end]);
                self.pos = end;
            }
            2 => {
                let len = read_varint(self.buf, &mut self.pos)? as usize;
                let end = self.pos.checked_add(len)?;
                if end > self.buf.len() {
                    return None;
                }
                record.bytes = Some(&self.buf[self.pos..end]);
                self.pos = end;
            }
            5 => {
                let end = (self.pos + 4).min(self.buf.len());
                record.bytes = Some(&self.buf[self.pos..end]);
                self.pos = end;
            }
            // group wire types (3/4) are not used by geoip.dat
            _ => return None,
        }
        Some(record)
    }
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos)?;
        *pos += 1;
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}
