use std::collections::BTreeMap;

use base64::engine::general_purpose::{
    STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
};
use base64::Engine;

use crate::error::{field_err, Error, Result};
use crate::node::{Transport, TransportKind};

/// Decode base64 as found in the wild: padded or not, standard or URL-safe.
///
/// Order matters. Most subscriptions are padded and end in `=`, so the padded
/// engines must be tried **first**: stripping the padding up front turns a
/// valid `...XYZ=` into an invalid length and every decoder then refuses it.
/// Unpadded input is still accepted, because panels that omit padding exist.
pub fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();

    // 1. exactly as given, padding included
    for engine in [&STANDARD, &URL_SAFE] {
        if let Ok(v) = engine.decode(cleaned.as_bytes()) {
            return Ok(v);
        }
    }

    // 2. padding stripped, unpadded engines
    let stripped = cleaned.trim_end_matches('=');
    if stripped.len() != cleaned.len() {
        for engine in [&URL_SAFE_NO_PAD, &STANDARD_NO_PAD] {
            if let Ok(v) = engine.decode(stripped.as_bytes()) {
                return Ok(v);
            }
        }
    }

    // 3. padding was wrong: re-pad to a multiple of four and try once more
    let mut padded = stripped.to_string();
    while padded.len() % 4 != 0 {
        padded.push('=');
    }
    if let Ok(v) = STANDARD.decode(padded.as_bytes()) {
        return Ok(v);
    }
    if let Ok(v) = URL_SAFE.decode(padded.as_bytes()) {
        return Ok(v);
    }

    Err(Error::Base64(format!(
        "not valid base64 ({} chars, {})",
        cleaned.chars().count(),
        &cleaned[..cleaned.len().min(24)]
    )))
}

pub fn b64_string(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn percent_decode(input: &str) -> String {
    percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .to_string()
}

pub fn percent_encode(input: &str) -> String {
    const SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(input, SET).to_string()
}

/// A hand-rolled `scheme://user@host:port/path?query#fragment` splitter.
///
/// `url::Url` normalizes and rejects too much for real-world proxy links
/// (unpadded base64 fragments, `=` in the authority, raw `|` in gRPC service
/// names...), so links are parsed structurally instead.
#[derive(Debug, Clone, Default)]
pub struct RawLink {
    pub scheme: String,
    pub userinfo: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub query: BTreeMap<String, String>,
    pub fragment: Option<String>,
    pub raw_query: String,
}

impl RawLink {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| Error::MalformedLink(format!("missing scheme: {}", truncate_public(input))))?;
        if scheme.is_empty() {
            return Err(Error::MalformedLink("empty scheme".into()));
        }
        let scheme = scheme.to_ascii_lowercase();

        let mut rest = rest;
        // authority ends at the first '/', '?' or '#'
        let auth_end = rest
            .find(['/', '?', '#'])
            .unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(auth_end);
        rest = tail;

        let (userinfo, hostport) = match authority.rfind('@') {
            Some(pos) => (Some(authority[..pos].to_string()), &authority[pos + 1..]),
            None => (None, authority),
        };

        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return Err(Error::MalformedLink("empty host".into()));
        }

        let (path, rest) = match rest.find(['?', '#']) {
            Some(pos) => {
                let (p, r) = rest.split_at(pos);
                (Some(p.to_string()), r)
            }
            None => (None, rest),
        };

        let (query_raw, fragment) = if let Some(stripped) = rest.strip_prefix('?') {
            match stripped.split_once('#') {
                Some((q, f)) => (q.to_string(), Some(f.to_string())),
                None => (stripped.to_string(), None),
            }
        } else if let Some(f) = rest.strip_prefix('#') {
            (String::new(), Some(f.to_string()))
        } else {
            (String::new(), None)
        };

        let query = parse_query(&query_raw);

        Ok(Self {
            scheme,
            userinfo: userinfo.filter(|u| !u.is_empty()).map(|u| percent_decode(&u)),
            host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
            port,
            path: path.filter(|p| !p.is_empty()).map(|p| percent_decode(&p)),
            query,
            fragment: fragment
                .filter(|f| !f.is_empty())
                .map(|f| percent_decode(&f)),
            raw_query: query_raw,
        })
    }

    pub fn port_or(&self, default: u16) -> Result<u16> {
        self.port
            .ok_or_else(|| Error::MalformedLink("missing port".into()))
            .or(Ok(default))
    }

    /// Query values are compared case-insensitively against known keys but the
    /// original casing is preserved in `extra`.
    pub fn q(&self, key: &str) -> Option<String> {
        self.query.get(key).cloned()
    }

    pub fn q_ci(&self, key: &str) -> Option<String> {
        self.query
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
    }

    pub fn has(&self, key: &str) -> bool {
        self.query.keys().any(|k| k.eq_ignore_ascii_case(key))
    }

    pub fn label(&self) -> Option<String> {
        self.fragment.clone().filter(|f| !f.is_empty())
    }
}

pub fn parse_query(raw: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

fn split_host_port(hostport: &str) -> Result<(String, Option<u16>)> {
    let hostport = hostport.trim_end_matches('/');
    if let Some(stripped) = hostport.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| Error::MalformedLink("unterminated ipv6 literal".into()))?;
        let port = match tail.strip_prefix(':') {
            Some(p) if !p.is_empty() => Some(parse_port(p)?),
            _ => None,
        };
        return Ok((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            Ok((h.to_string(), Some(parse_port(p)?)))
        }
        _ => Ok((hostport.to_string(), None)),
    }
}

pub fn parse_port(raw: &str) -> Result<u16> {
    raw.trim()
        .parse::<u16>()
        .map_err(|_| field_err("port", raw))
}

/// `true`, `1`, `yes` -> true
pub fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Bookkeeping keys the library adds itself (`geo::annotate` and friends).
///
/// They must never reach a share link: they are our own metadata, not part of
/// the node, and clients would just ignore an unknown `country=` parameter.
pub const INTERNAL_MARKERS: &[&str] = &["country", "city", "anycast", "ip", "cascade"];

/// Keys that have a first-class field on [`Node`] and must not leak into `extra`.
pub const KNOWN_QUERY_KEYS: &[&str] = &[
    "type",
    "security",
    "encryption",
    "sni",
    "peer",
    "host",
    "path",
    "alpn",
    "fp",
    "pbk",
    "sid",
    "spx",
    "flow",
    "mode",
    "servicename",
    "serviceName",
    "headerType",
    "seed",
    "allowInsecure",
    "insecure",
    "allow_insecure",
    "skip-cert-verify",
    "obfs",
    "obfs-password",
    "obfsParam",
    "mport",
    "port-hopping",
    "up",
    "down",
    "upmbps",
    "downmbps",
    "congestion_control",
    "alpn",
    "level",
    "remarks",
    "name",
];

pub fn known_query_key(key: &str) -> bool {
    KNOWN_QUERY_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key))
}

/// Collect query params that are not modelled into [`Node::extra`].
/// Build a link query string preserving insertion order.
pub fn build_query(items: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in items {
        if out.is_empty() {
            out.push('?');
        } else {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}

/// Append transport params to a query string, skipping the defaults.
pub fn build_query_with_transport(items: &[(String, String)], t: &Transport) -> String {
    let mut items = items.to_vec();
    if t.kind != TransportKind::Tcp {
        items.push(("type".into(), t.kind.as_str().to_string()));
    }
    for (key, value) in [
        ("path", &t.path),
        ("host", &t.host),
        ("serviceName", &t.service_name),
        ("mode", &t.mode),
        ("headerType", &t.header_type),
        ("seed", &t.seed),
    ] {
        if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
            items.push((key.into(), v.to_string()));
        }
    }
    build_query(&items)
}

/// Pull transport params out of a parsed link query.
pub fn transport_from_query(raw: &RawLink) -> Transport {
    let declared = raw.q_ci("type");
    let parsed = declared
        .as_deref()
        .map(TransportKind::parse)
        .unwrap_or_default();

    let mut t = Transport {
        // An unrecognised `type` falls back to plain TCP rather than being
        // carried through. Providers do pad the field with advertising — a real
        // one is `type=tcp#📪83@oneclickvpnkeys vless://…` — and the intent there
        // is plainly `tcp`. Passing the string on would put it in `network`,
        // where no core accepts it, and a config with one such node refuses to
        // start at all: one poisoned node takes down the whole profile.
        kind: if parsed.is_known() {
            parsed
        } else {
            TransportKind::Tcp
        },
        path: raw.q_ci("path"),
        host: raw.q_ci("host"),
        service_name: raw.q_ci("serviceName"),
        mode: raw.q_ci("mode"),
        header_type: raw.q_ci("headerType"),
        seed: raw.q_ci("seed"),
        extra: Default::default(),
        raw: None,
    };
    if let Some(k) = declared {
        if !TransportKind::parse(&k).is_known() {
            // Kept for the round-trip and for the junk filter to see, under a
            // name that cannot collide with a real parameter.
            t.extra.insert("type-raw".into(), k);
        }
    }
    t
}

pub fn collect_extra(raw: &RawLink) -> BTreeMap<String, String> {
    raw.query
        .iter()
        .filter(|(k, _)| !known_query_key(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// `address` may be a hostname or an IP; resolve later.
pub fn is_ip_like(address: &str) -> bool {
    address.parse::<std::net::IpAddr>().is_ok()
}

pub fn truncate_public(s: &str) -> String {
    s.chars().take(48).collect()
}
