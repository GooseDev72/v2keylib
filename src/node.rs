use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Transport layer protocol used to multiplex the proxy stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    #[default]
    Tcp,
    Ws,
    Http,
    H2,
    Httpupgrade,
    Grpc,
    Quic,
    Kcp,
    Xhttp,
    /// SplitHTTP — deprecated alias of XHTTP in XRay.
    Splithttp,
    /// Anything the source format knows but this library does not model.
    Other(String),
}

impl TransportKind {
    pub fn as_str(&self) -> &str {
        match self {
            TransportKind::Tcp => "tcp",
            TransportKind::Ws => "ws",
            TransportKind::Http => "http",
            TransportKind::H2 => "h2",
            TransportKind::Httpupgrade => "httpupgrade",
            TransportKind::Grpc => "grpc",
            TransportKind::Quic => "quic",
            TransportKind::Kcp => "kcp",
            TransportKind::Xhttp => "xhttp",
            TransportKind::Splithttp => "splithttp",
            TransportKind::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" | "raw" | "" => TransportKind::Tcp,
            "ws" | "websocket" => TransportKind::Ws,
            "http" => TransportKind::Http,
            "h2" | "http2" => TransportKind::H2,
            "httpupgrade" => TransportKind::Httpupgrade,
            "grpc" | "gun" => TransportKind::Grpc,
            "quic" => TransportKind::Quic,
            "kcp" | "mkcp" => TransportKind::Kcp,
            "xhttp" | "splithttp" => TransportKind::Xhttp,
            other => TransportKind::Other(other.to_string()),
        }
    }

    /// Whether this is a transport XRay actually knows.
    ///
    /// Providers pad `type=` with advertising now and then — a real one, seen in
    /// the wild as `type=tcp#📪83@oneclickvpnkeys vless://…` — and that decodes
    /// to a value no core accepts. Passing it through produces a config that
    /// refuses to start, which takes the *whole profile* down with it rather
    /// than just the one bad node, so it has to be caught at parse time.
    pub fn is_known(&self) -> bool {
        !matches!(self, TransportKind::Other(_))
    }
}

/// Transport settings shared by all protocols.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Transport {
    #[serde(default)]
    pub kind: TransportKind,
    /// Request path (ws / http / h2 / xhttp / splithttp).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `Host` header / http host list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// gRPC service name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// gRPC / xhttp mode (`multi`, `gun`, `packet-up`, `stream-one`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// kcp/quic obfuscation seed (mKCP `headerType` + `seed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// tcp http obfs / gRPC header masquerade name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    /// Any transport field this library does not model, kept for round-tripping.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
    /// Unmodelled transport block, verbatim as JSON text (e.g. XHTTP's
    /// `extra` with its nested `xmux`). Kept as a string so JSON scalars keep
    /// their original type and nested objects stay objects instead of being
    /// flattened into query params and re-parsed with the wrong types.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

impl Transport {
    pub fn tcp() -> Self {
        Self::default()
    }

    pub fn kind(&self) -> &TransportKind {
        &self.kind
    }
}

/// TLS security layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    #[default]
    None,
    Tls,
    Reality,
}

impl Security {
    pub fn as_str(&self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls => "tls",
            Security::Reality => "reality",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "tls" | "xtls" => Security::Tls,
            "reality" => Security::Reality,
            _ => Security::None,
        }
    }
}

/// Proxy protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    /// Hysteria v1 (`hy://`).
    Hysteria,
    /// Hysteria 2 / TUIC-less (`hy2://`, `hysteria2://`).
    Hysteria2,
    Shadowsocks,
    Tuic,
    Socks,
    Http,
    Wireguard,
    Anytls,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
            Protocol::Hysteria => "hysteria",
            Protocol::Hysteria2 => "hysteria2",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Tuic => "tuic",
            Protocol::Socks => "socks",
            Protocol::Http => "http",
            Protocol::Wireguard => "wireguard",
            Protocol::Anytls => "anytls",
        }
    }

    /// True for protocols that rely on a uuid (`vless`, `vmess`, `anytls`).
    pub fn requires_uuid(&self) -> bool {
        matches!(self, Protocol::Vless | Protocol::Vmess | Protocol::Anytls)
    }
}

/// A comma-separated host list, as a set: order carries no meaning in a header,
/// but `a,b` and `b,a` are the same host list and must not make two nodes
/// look different.
fn host_list(host: &str) -> String {
    let mut hosts: Vec<String> = host
        .split(',')
        .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    hosts.sort();
    hosts.join(",")
}

/// `alpn=h2,h3` and `alpn=h3,h2` are the same node, and the same is true of the
/// unmodelled transport params, which have no order of their own.
/// An empty value and an absent one are the same value.
fn present(value: Option<&str>) -> &str {
    value.map(str::trim).filter(|v| !v.is_empty()).unwrap_or("")
}

/// The request path, spelled the way XRay reads it.
///
/// An unset path is `/`, so `path=/` and no `path` at all are one config written
/// twice — which is how the same node arrives from two providers. Transports
/// that have no path keep theirs empty.
fn path<'a>(kind: &TransportKind, path: Option<&'a str>) -> &'a str {
    let given = path.map(str::trim).filter(|p| !p.is_empty());
    match given {
        Some(p) => p,
        None if matches!(
            kind,
            TransportKind::Ws
                | TransportKind::Http
                | TransportKind::H2
                | TransportKind::Httpupgrade
                | TransportKind::Xhttp
        ) =>
        {
            "/"
        }
        None => "",
    }
}

fn sorted_list(values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.join(",")
}

fn sorted_map(values: &BTreeMap<String, String>) -> String {
    values
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// One regional indicator symbol as an uppercase letter: 🇦 -> `A`.
fn regional_indicator(c: char) -> Option<char> {
    match u32::from(c) {
        0x1F1E6..=0x1F1FF => char::from_u32(u32::from(c) - 0x1F1E6 + u32::from('A')),
        _ => None,
    }
}

/// A normalized, format-agnostic proxy node ("key").
///
/// Every supported input format is parsed into this structure and every output
/// format is rendered from it, which makes the library a lossless-ish hub for
/// conversions between clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    /// uuid for vless/vmess/anytls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// password for trojan / anytls, or Hysteria2 `auth`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// shadowsocks cipher / hysteria1 obfuscation method.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default)]
    pub security: Security,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// REALITY `publicKey` / short link id style keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// REALITY `shortId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    /// REALITY `spiderX`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
    /// vless flow (`xtls-rprx-vision`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default)]
    pub transport: Transport,
    /// Hysteria 2 port hopping, e.g. `10000-20000` or `443,8443`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_hopping: Option<String>,
    /// Hysteria/TUIC bandwidth in Mbps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down_mbps: Option<u32>,
    /// Hysteria 1 `obfs` param / TUIC `congestion_control`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    /// Human readable name (fragment / mihomo `name` / sing-box `tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Unmodelled query params, preserved for round-trips.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, String>,
}

impl Node {
    /// Keys this library adds for its own bookkeeping rather than for the link.
    ///
    /// They live in [`Node::extra`] because that is where anything unmodelled
    /// goes, which means they would otherwise be written into every rendered
    /// link as `?country=NL&source=remiuc` — noise in the client's node list, and
    /// wrong, since no server reads them. Stripped on the way out.
    pub const INTERNAL_KEYS: &'static [&'static str] = &["country", "exit", "source", "channel"];

    /// Drop this library's own annotations, keeping the ones a real link has.
    pub fn without_annotations(mut self) -> Node {
        for key in Self::INTERNAL_KEYS {
            self.extra.remove(*key);
        }
        self
    }
    pub fn new(protocol: Protocol, address: impl Into<String>, port: u16) -> Self {
        Self {
            protocol,
            address: address.into(),
            port,
            uuid: None,
            password: None,
            method: None,
            security: Security::None,
            sni: None,
            alpn: Vec::new(),
            fingerprint: None,
            public_key: None,
            short_id: None,
            spider_x: None,
            flow: None,
            transport: Transport::tcp(),
            port_hopping: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            allow_insecure: false,
            label: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    pub fn with_security(mut self, security: Security) -> Self {
        self.security = security;
        self
    }

    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// `address:port` as used for tcp probing and dedup keys.
    pub fn socket_addr(&self) -> String {
        if self.address.contains(':') && !self.address.starts_with('[') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }

    /// Stable identity: `protocol ip uuid port sni security`. Used for dedup.
    pub fn dedup_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.protocol.as_str(),
            self.address.to_ascii_lowercase(),
            self.uuid.as_deref().unwrap_or_default(),
            self.port,
            self.sni.as_deref().unwrap_or_default().to_ascii_lowercase(),
            self.security.as_str(),
        )
    }

    /// Everything that decides whether this node *is* this node.
    ///
    /// [`dedup_key`](Self::dedup_key) answers a weaker question — same server,
    /// same credential, same TLS front — and two links that pass it can still be
    /// different nodes: one over ws at `/a`, the other over grpc with a
    /// different `serviceName`; one with `flow=xtls-rprx-vision`, the same
    /// endpoint without it. In a merged list from a dozen sources those are two
    /// rows in a client's server list that do not behave the same, and a user
    /// cannot tell which one to keep.
    ///
    /// So this key counts every parameter that changes the bytes on the wire:
    /// credentials, the whole TLS identity, the whole transport block including
    /// the unmodelled one, flow, bandwidth, port hopping. What it leaves out is
    /// the name and [`extra`](Self::extra): providers rewrite remarks freely,
    /// and the params they invent are almost always advertising rather than
    /// configuration — `?Telegram=@channel` is the same node wearing a badge.
    pub fn strict_key(&self) -> String {
        let mut key = String::with_capacity(160);
        let mut push = |part: &str| {
            key.push_str(part);
            // `|` inside a value would let two different nodes spell the same
            // key; lengths make the fields unambiguous without escaping.
            key.push('|');
        };

        push(self.protocol.as_str());
        push(
            self.address
                .trim_end_matches('.')
                .to_ascii_lowercase()
                .as_str(),
        );
        push(&self.port.to_string());
        push(
            self.uuid
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(self.password.as_deref().unwrap_or_default());
        push(
            self.method
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(self.security.as_str());
        push(
            self.sni
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(&sorted_list(&self.alpn));
        push(
            self.fingerprint
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(self.public_key.as_deref().unwrap_or_default());
        push(
            self.short_id
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(self.spider_x.as_deref().unwrap_or_default());
        push(
            self.flow
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(if self.allow_insecure { "1" } else { "0" });

        push(self.transport.kind.as_str());
        push(path(&self.transport.kind, self.transport.path.as_deref()));
        push(&host_list(
            self.transport.host.as_deref().unwrap_or_default(),
        ));
        push(present(self.transport.service_name.as_deref()));
        push(
            self.transport
                .mode
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(
            self.transport
                .seed
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(
            self.transport
                .header_type
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        push(&sorted_map(&self.transport.extra));
        push(self.transport.raw.as_deref().unwrap_or_default());

        push(self.port_hopping.as_deref().unwrap_or_default());
        push(&self.up_mbps.map(|v| v.to_string()).unwrap_or_default());
        push(&self.down_mbps.map(|v| v.to_string()).unwrap_or_default());
        push(
            self.obfs
                .as_deref()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .as_str(),
        );
        key
    }

    /// Label if the node has one, otherwise a readable generated name.
    pub fn display_name(&self, index: usize) -> String {
        match self.label.as_deref() {
            Some(l) if !l.is_empty() => l.to_string(),
            _ => format!(
                "{}-{}-{}-{}",
                self.protocol.as_str(),
                self.address,
                self.port,
                index
            ),
        }
    }

    /// Names for a whole batch that are unique.
    ///
    /// Proxy names address entries in Mihomo/Clash groups and must not
    /// collide, but free subscriptions repeat the same label across many
    /// nodes (often one server offered with a dozen fingerprints), so a bare
    /// label produces a config where most entries shadow each other. A unique
    /// label is used as is; a repeated one is qualified with whatever actually
    /// tells the nodes apart, fingerprint first because that is what these
    /// subscriptions vary.
    pub fn unique_names(nodes: &[Node]) -> Vec<String> {
        use std::collections::HashMap;

        let mut counts: HashMap<&str, usize> = HashMap::new();
        for node in nodes {
            if let Some(label) = node.label.as_deref().filter(|l| !l.is_empty()) {
                *counts.entry(label).or_default() += 1;
            }
        }

        let mut names = Vec::with_capacity(nodes.len());
        let mut taken: HashMap<String, usize> = HashMap::new();
        for (index, node) in nodes.iter().enumerate() {
            let base = node.display_name(index);
            let name = if counts.get(base.as_str()).copied().unwrap_or(0) <= 1 {
                base
            } else {
                let qualifier = node
                    .fingerprint
                    .as_deref()
                    .filter(|f| !f.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        node.sni
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| format!("{}-{}", node.address, node.port));
                format!("{base} · {qualifier}")
            };

            // the qualifier can still collide (same fp, same sni, same label)
            let seen = taken.entry(name.clone()).or_default();
            *seen += 1;
            names.push(if *seen > 1 {
                format!("{name} #{}", *seen)
            } else {
                name
            });
        }
        names
    }

    /// Countries named by the node's own label, in the order they appear.
    ///
    /// Free subscriptions often spell out the intended chain with an arrow
    /// (`🇷🇺➜🇵🇱` means "enter in RU, leave in PL"), and that chain is the only
    /// statement about the cascade the publisher ever makes. It is also often
    /// fiction, which is why it is exposed next to the measured exit rather
    /// than used on its own.
    pub fn claimed_route(&self) -> Vec<String> {
        let Some(label) = self.label.as_deref() else {
            return Vec::new();
        };
        let chars: Vec<char> = label.chars().collect();
        let mut codes = Vec::new();
        let mut i = 0;
        while i + 1 < chars.len() {
            // regional indicators come in pairs and encode the two letters
            if let (Some(a), Some(b)) = (
                regional_indicator(chars[i]),
                regional_indicator(chars[i + 1]),
            ) {
                codes.push(format!("{}{}", a, b));
                i += 2;
            } else {
                i += 1;
            }
        }
        codes
    }

    /// The country the label claims the connection finally leaves from.
    pub fn claimed_exit(&self) -> Option<String> {
        self.claimed_route().pop()
    }

    /// Resolve SNI falling back to the host header, then to the address.
    pub fn effective_sni(&self) -> Option<String> {
        self.sni.clone().filter(|s| !s.is_empty()).or_else(|| {
            self.transport
                .host
                .clone()
                .and_then(|h| h.split(',').next().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
        })
    }

    /// Host header value used for http-ish probes.
    pub fn probe_host(&self) -> Option<String> {
        self.effective_sni()
    }
}
