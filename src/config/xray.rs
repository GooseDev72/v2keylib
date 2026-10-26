//! XRay / v2fly JSON configuration.
//!
//! ```json
//! { "outbounds": [ { "protocol": "vless", "settings": {...},
//!                    "streamSettings": {...} } ],
//!   "routing": { "balancers": [ { "tag": "bal", "selector": ["a","b"],
//!                                 "strategy": {"type":"random"} } ],
//!                "rules": [ { "type": "field", "balancerTag": "bal" } ] } }
//! ```
//!
//! Balancers live under `routing`, not at the top level: XRay has no such field,
//! and a `balancerTag` pointing at a balancer nobody declared makes the whole
//! config fail to start.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::{BalancerKind, BalancerSpec, Bundle, Group};
use crate::error::{Error, Result};
use crate::node::{Node, Protocol, Security, Transport, TransportKind};
use crate::util::split_list;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XrayConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbounds: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbounds: Option<Vec<Outbound>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balancers: Option<Vec<Balancer>>,
    /// v2fly/XRay `observatory` / `burstObservatory`: health-checking groups
    /// used as routing targets without an explicit balancer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observatory: Option<Observatory>,
    #[serde(
        default,
        rename = "burstObservatory",
        skip_serializing_if = "Option::is_none"
    )]
    pub burst_observatory: Option<Observatory>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Observatory {
    #[serde(default, rename = "subjectSelector", skip_serializing_if = "Vec::is_empty")]
    pub subject_selector: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_url: Option<String>,
    #[serde(
        default,
        rename = "probeInterval",
        skip_serializing_if = "Option::is_none"
    )]
    pub probe_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_concurrency: Option<bool>,
    /// `burstObservatory` spells its probe settings this way instead of the
    /// `probeUrl`/`probeInterval` pair the plain `observatory` uses.
    #[serde(
        default,
        rename = "pingConfig",
        skip_serializing_if = "Option::is_none"
    )]
    pub ping_config: Option<PingConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connectivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<u32>,
}

impl Observatory {
    fn to_group(&self, name: &str, kind: BalancerKind) -> Group {
        let ping = self.ping_config.as_ref();
        let url = self
            .probe_url
            .clone()
            .or_else(|| ping.and_then(|p| p.destination.clone()))
            .or_else(|| ping.and_then(|p| p.connectivity.clone()));
        let raw_interval = self
            .probe_interval
            .as_deref()
            .or_else(|| ping.and_then(|p| p.interval.as_deref()));
        let interval = raw_interval.and_then(crate::config::singbox::parse_duration);
        Group {
            name: name.to_string(),
            kind,
            members: self.subject_selector.clone(),
            fallback: None,
            url,
            interval,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Outbound {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default)]
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_settings: Option<StreamSettings>,
    #[serde(
        default,
        rename = "streamSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_settings_camel: Option<StreamSettings>,
}

impl Outbound {
    pub fn streams(&self) -> Option<&StreamSettings> {
        self.stream_settings.as_ref().or(self.stream_settings_camel.as_ref())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamSettings {
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub security: String,
    #[serde(default, rename = "tlsSettings", skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<TlsSettings>,
    #[serde(
        default,
        rename = "realitySettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub reality_settings: Option<RealitySettings>,
    #[serde(default, rename = "wsSettings", skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<WsSettings>,
    #[serde(
        default,
        rename = "httpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_settings: Option<HttpSettings>,
    #[serde(
        default,
        rename = "httpupgradeSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub httpupgrade_settings: Option<HttpUpgradeSettings>,
    #[serde(
        default,
        rename = "xhttpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub xhttp_settings: Option<XhttpSettings>,
    #[serde(
        default,
        rename = "splithttpSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub splithttp_settings: Option<XhttpSettings>,
    #[serde(
        default,
        rename = "grpcSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(default, rename = "tcpSettings", skip_serializing_if = "Option::is_none")]
    pub tcp_settings: Option<TcpSettings>,
    #[serde(default, rename = "kcpSettings", skip_serializing_if = "Option::is_none")]
    pub kcp_settings: Option<KcpSettings>,
    #[serde(default, rename = "quicSettings", skip_serializing_if = "Option::is_none")]
    pub quic_settings: Option<QuicSettings>,
    /// Hysteria2 transport credentials. XRay spells the protocol `hysteria`
    /// with `version: 2`; this block carries the password.
    #[serde(
        default,
        rename = "hysteriaSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub hysteria_settings: Option<HysteriaSettings>,
    /// Newer XRay releases express Hysteria2 obfuscation and port hopping as
    /// final masks rather than dedicated settings.
    #[serde(
        default,
        rename = "finalmask",
        skip_serializing_if = "Option::is_none"
    )]
    pub final_mask: Option<FinalMask>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsSettings {
    #[serde(default, rename = "serverName", skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, rename = "fingerprint", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(
        default,
        rename = "allowInsecure",
        skip_serializing_if = "Option::is_none"
    )]
    pub allow_insecure: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealitySettings {
    #[serde(default, rename = "serverName", skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, rename = "fingerprint", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, rename = "publicKey", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, rename = "shortId", skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
    #[serde(default, rename = "spiderX", skip_serializing_if = "Option::is_none")]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WsSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<Value>,
    #[serde(default, rename = "maxEarlyData", skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub host: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpUpgradeSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XhttpSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// `headers` is a first-class field in XHTTP (field 4 of the proto), and
    /// XRay rejects a `host` key inside it, so it is kept separate from `host`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// xhttp tuning knobs (`scMaxEachPostBytes`, `xmux`, ...). Nested and
    /// typed-free on purpose: the set grows between XRay releases, so keeping
    /// the raw JSON is the only way to round-trip a config without loss.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
    /// Everything else this library does not model, flattened. Captured so that
    /// configs *without* an `extra` block do not silently lose their tuning.
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub rest: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrpcSettings {
    #[serde(default, rename = "serviceName", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, rename = "multiMode", skip_serializing_if = "Option::is_none")]
    pub multi_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
}

/// XRay's TCP transport: the header masquerade (`headerType=http`) and the
/// proxy protocol. A node using it looks like a raw node on the wire, so
/// dropping this silently breaks the connection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpSettings {
    #[serde(
        default,
        rename = "acceptProxyProtocol",
        skip_serializing_if = "Option::is_none"
    )]
    pub accept_proxy_protocol: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<TcpHeader>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpHeader {
    #[serde(rename = "type")]
    pub kind: String,
    /// Kept as raw JSON: it holds a path *list*, a method and arbitrary
    /// headers, none of which fit into the link format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KcpSettings {
    #[serde(default, rename = "headerType", skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuicSettings {
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default, rename = "key", skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, rename = "headerType", skip_serializing_if = "Option::is_none")]
    pub header_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HysteriaSettings {
    #[serde(default)]
    pub version: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
}

/// The part of XRay's `finalmask` this library understands.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FinalMask {
    #[serde(default, rename = "udp", skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<Mask>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Mask {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub settings: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Balancer {
    pub tag: String,
    #[serde(default)]
    pub selector: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_tag: Option<String>,
    #[serde(default)]
    pub strategy: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalancerStrategy {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<Value>,
}

// ---------------------------------------------------------------- parsing

pub fn parse(input: &str) -> Result<Bundle> {
    let text = strip_bom(input);
    let value: Value = serde_json::from_str(text)?;
    let cfg: XrayConfig = serde_json::from_value(value)?;

    let mut bundle = Bundle::default();
    // A "balancer-only" config points inbound traffic at a balancer tag.
    let routing_tag = routing_balancer_tag(&cfg);
    // XRay keeps balancers under `routing`; a few panels write them top-level
    // instead. Read both, `routing` first, so a provider's config keeps the
    // groups it actually declares.
    let mut balancers = routing_balancers(&cfg);
    balancers.extend(cfg.balancers.clone().unwrap_or_default());

    for ob in cfg.outbounds.unwrap_or_default() {
        if ob.protocol == "freedom" || ob.protocol == "blackhole" || ob.protocol == "dns" {
            continue;
        }
        if let Some(mut node) = parse_outbound(&ob)? {
            if node.label.is_none() {
                node.label = ob.tag.clone();
            }
            bundle.nodes.push(node);
        }
    }

    for bal in balancers {
        let kind = bal
            .strategy
            .as_ref()
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            .and_then(BalancerKind::parse)
            .unwrap_or(BalancerKind::Random);
        let (url, interval) = strategy_probe(bal.strategy.as_ref());
        bundle.groups.push(Group {
            name: bal.tag.clone(),
            kind,
            members: bal.selector.clone(),
            fallback: bal.fallback_tag.clone(),
            url,
            interval,
        });
    }

    for (obs, name, kind) in [
        (cfg.observatory.as_ref(), "observatory", BalancerKind::LeastPing),
        (
            cfg.burst_observatory.as_ref(),
            "burst",
            BalancerKind::LeastPing,
        ),
    ] {
        if let Some(obs) = obs {
            if !obs.subject_selector.is_empty() {
                bundle.groups.push(obs.to_group(name, kind));
            }
        }
    }

    if let Some(tag) = routing_tag {
        if !bundle.groups.iter().any(|g| g.name == tag) {
            let members: Vec<String> = bundle.nodes.iter().filter_map(|n| n.label.clone()).collect();
            bundle.groups.push(Group {
                name: tag.clone(),
                kind: BalancerKind::Random,
                members,
                fallback: None,
                url: None,
                interval: None,
            });
        }
    }

    Ok(bundle)
}

pub(crate) fn strip_bom(input: &str) -> &str {
    input.strip_prefix('\u{feff}').unwrap_or(input)
}

/// Find the balancer tag referenced by the catch-all routing rule.
fn routing_balancer_tag(cfg: &XrayConfig) -> Option<String> {
    let routing = cfg.routing.as_ref()?;
    let rules = routing.get("rules")?.as_array()?;
    for rule in rules {
        if rule.get("inboundTag").is_none() {
            if let Some(tag) = rule.get("balancerTag").and_then(Value::as_str) {
                return Some(tag.to_string());
            }
        }
    }
    None
}

fn routing_balancers(cfg: &XrayConfig) -> Vec<Balancer> {
    let Some(routing) = cfg.routing.as_ref() else {
        return Vec::new();
    };
    let Some(raw) = routing.get("balancers") else {
        return Vec::new();
    };
    // `routing` is kept as an opaque `Value` (it carries rules the typed
    // structs do not model), so the balancers inside it are deserialized on
    // their own rather than as part of the config.
    serde_json::from_value(raw.clone()).unwrap_or_default()
}

fn strategy_probe(strategy: Option<&Value>) -> (Option<String>, Option<u64>) {
    let Some(s) = strategy else { return (None, None) };
    let settings = s.get("settings");
    let url = settings
        .and_then(|s| s.get("probeURL"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let interval = settings
        .and_then(|s| s.get("probeInterval"))
        .and_then(Value::as_str)
        .and_then(|v| v.trim_start_matches(['"', '\'']).trim_end_matches(['"', '\'']).parse().ok());
    (url, interval)
}

pub fn parse_outbound(ob: &Outbound) -> Result<Option<Node>> {
    let settings = ob.settings.clone().unwrap_or(Value::Null);
    let streams = ob.streams().cloned().unwrap_or_default();
    // XRay has one outbound protocol (`hysteria`) whose version 2 is Hysteria2.
    // The version may live in `settings` or in `hysteriaSettings`; both are
    // accepted, because XRay itself reads the latter and examples use both.
    let hysteria_v2 = ob.protocol.eq_ignore_ascii_case("hysteria")
        && (settings.get("version").and_then(Value::as_u64) == Some(2)
            || streams
                .hysteria_settings
                .as_ref()
                .map(|h| h.version == 2)
                .unwrap_or(false));

    let (protocol, address, port, users) = match ob.protocol.as_str() {
        "vless" | "vmess" => {
            let vnext = settings
                .get("vnext")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .ok_or(Error::MissingField("vnext"))?;
            let address = vnext
                .get("address")
                .and_then(Value::as_str)
                .ok_or(Error::MissingField("address"))?
                .to_string();
            let port = vnext
                .get("port")
                .and_then(Value::as_u64)
                .ok_or(Error::MissingField("port"))? as u16;
            let users = vnext
                .get("users")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            (ob.protocol.clone(), address, port, users)
        }
        "trojan" => {
            let servers = settings
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .ok_or(Error::MissingField("servers"))?;
            let address = servers
                .get("address")
                .and_then(Value::as_str)
                .ok_or(Error::MissingField("address"))?
                .to_string();
            let port = servers
                .get("port")
                .and_then(Value::as_u64)
                .ok_or(Error::MissingField("port"))? as u16;
            (ob.protocol.clone(), address, port, Vec::new())
        }
        "socks" | "http" => {
            let servers = settings
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .ok_or(Error::MissingField("servers"))?;
            (
                ob.protocol.clone(),
                servers
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                servers.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
                Vec::new(),
            )
        }
        "shadowsocks" => {
            let servers = settings
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .ok_or(Error::MissingField("servers"))?;
            (
                ob.protocol.clone(),
                servers
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                servers.get("port").and_then(Value::as_u64).unwrap_or(0) as u16,
                Vec::new(),
            )
        }
        "hysteria" | "hysteria2" | "tuic" | "anytls" => {
            let servers = settings
                .get("servers")
                .and_then(Value::as_array)
                .and_then(|a| a.first());
            let servers = match servers {
                Some(s) => s.clone(),
                None => settings.clone(),
            };
            let address = servers
                .get("address")
                .or_else(|| servers.get("server"))
                .and_then(Value::as_str)
                .ok_or(Error::MissingField("address"))?
                .to_string();
            let port = servers
                .get("port")
                .or_else(|| servers.get("server_port"))
                .and_then(Value::as_u64)
                .ok_or(Error::MissingField("port"))? as u16;
            (ob.protocol.clone(), address, port, Vec::new())
        }
        _ => return Ok(None),
    };

    let proto = match protocol.as_str() {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "hysteria" => {
            if hysteria_v2 {
                Protocol::Hysteria2
            } else {
                Protocol::Hysteria
            }
        }
        "hysteria2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "anytls" => Protocol::Anytls,
        "socks" => Protocol::Socks,
        "http" => Protocol::Http,
        "shadowsocks" => Protocol::Shadowsocks,
        _ => return Ok(None),
    };

    let mut node = Node::new(proto, address, port);

    if let Some(user) = users.first() {
        node.uuid = user.get("id").and_then(Value::as_str).map(str::to_string);
        // An empty `flow` string means "unset", not "empty flow".
        node.flow = user
            .get("flow")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(str::to_string);
        if let Some(enc) = user.get("encryption").and_then(Value::as_str) {
            if !enc.is_empty() && !enc.eq_ignore_ascii_case("none") {
                node.extra.insert("encryption".into(), enc.to_string());
            }
        }
        if let Some(level) = user.get("level").and_then(Value::as_u64) {
            node.extra.insert("level".into(), level.to_string());
        }
    }

    // credentials for trojan / hysteria family
    let cred = settings
        .get("servers")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or_else(|| settings.clone());
    node.password = cred
        .get("password")
        .or_else(|| cred.get("auth"))
        .or_else(|| cred.get("auth_str"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if node.password.is_none() {
        node.password = streams
            .hysteria_settings
            .as_ref()
            .and_then(|h| h.auth.as_deref())
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string);
    }
    node.uuid = node.uuid.or_else(|| {
        cred.get("uuid")
            .or_else(|| cred.get("user"))
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    node.method = cred
        .get("method")
        .or_else(|| cred.get("cipher"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(obfs) = cred.get("obfs") {
        let name = obfs
            .as_str()
            .map(str::to_string)
            .or_else(|| obfs.get("type").and_then(Value::as_str).map(str::to_string));
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            node.obfs = Some(name);
        }
    }
    if let Some(hop) = cred
        .get("ports")
        .or_else(|| cred.get("hop_ports"))
        .and_then(Value::as_str)
    {
        node.port_hopping = Some(hop.to_string());
    }
    node.up_mbps = cred.get("up_mbps").and_then(Value::as_u64).map(|v| v as u32);
    node.down_mbps = cred.get("down_mbps").and_then(Value::as_u64).map(|v| v as u32);

    apply_streams(&mut node, &streams);
    Ok(Some(node))
}

pub fn apply_streams(node: &mut Node, streams: &StreamSettings) {
    node.security = Security::parse(&streams.security);
    if node.security == Security::None && protocol_is_tls_only(node) {
        node.security = Security::Tls;
    }
    // `network: hysteria` is how XRay names the Hysteria2 transport. It is not
    // a transport field in the link format (the protocol already implies QUIC),
    // so keeping it as a generic transport would make the same node hash
    // differently depending on which format it came from.
    if !streams.network.is_empty() && streams.network != "hysteria" {
        node.transport.kind = TransportKind::parse(&streams.network);
    }

    if let Some(tls) = &streams.tls_settings {
        node.sni = tls.server_name.clone();
        node.alpn = tls.alpn.clone();
        node.fingerprint = tls.fingerprint.clone();
        if tls.allow_insecure == Some(true) {
            node.allow_insecure = true;
        }
    }
    if let Some(reality) = &streams.reality_settings {
        node.security = Security::Reality;
        node.sni = reality.server_name.clone().or(node.sni.take());
        node.fingerprint = reality.fingerprint.clone().or(node.fingerprint.take());
        node.public_key = reality.public_key.clone();
        node.short_id = reality.short_id.clone();
        node.spider_x = reality.spider_x.clone();
    }
    if let Some(ws) = &streams.ws_settings {
        node.transport.kind = TransportKind::Ws;
        node.transport.path = ws.path.clone();
        node.transport.host = ws
            .headers
            .as_ref()
            .and_then(|h| h.get("Host").or_else(|| h.get("host")))
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if let Some(h) = &streams.httpupgrade_settings {
        node.transport.kind = TransportKind::Httpupgrade;
        node.transport.path = h.path.clone();
        node.transport.host = h.host.clone();
    }
    let xhttp = streams.xhttp_settings.as_ref().or(streams.splithttp_settings.as_ref());
    if let Some(x) = xhttp {
        node.transport.kind = TransportKind::Xhttp;
        node.transport.path = x.path.clone();
        node.transport.host = x.host.clone();
        node.transport.mode = x.mode.clone();

        // `extra` is not a bag of tunables: XRay unmarshals it as a whole
        // SplitHTTPConfig and lets it *replace* the outer object, except that
        // outer host/path/mode win. Top-level fields are the fallback when
        // `extra` is absent, so the effective block is `extra` or the rest.
        let effective: serde_json::Map<String, Value> = match &x.extra {
            Some(Value::Object(m)) => m.clone(),
            Some(_) => Default::default(),
            None => x.rest.clone(),
        };
        if !effective.is_empty() {
            let mut block = serde_json::Map::new();
            for (k, v) in &effective {
                // host/path/mode/headers are handled explicitly, and `extra`
                // must not be copied into itself or the block stops being
                // idempotent across round trips.
                if matches!(k.as_str(), "host" | "path" | "mode" | "headers" | "extra") {
                    continue;
                }
                // `null` means "not set" in these structs; carrying it through
                // would resurrect as an explicit null after re-parsing.
                if v.is_null() {
                    continue;
                }
                block.insert(k.clone(), v.clone());
            }
            if let Some(headers) = &x.headers {
                if !headers.is_empty() {
                    block.insert(
                        "headers".into(),
                        serde_json::to_value(headers).unwrap_or(Value::Null),
                    );
                }
            }
            let block = Value::Object(block);
            node.transport.extra = xhttp_extra_to_strings(&block);
            node.transport.raw = serde_json::to_string(&block).ok();
        }
        // A `Host` header is how XHTTP sends the SNI-alike target; expose it as
        // the transport host so share links carry it.
        if node.transport.host.is_none() {
            node.transport.host = x
                .headers
                .as_ref()
                .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone()));
        }
    }
    if let Some(h) = &streams.http_settings {
        if !h.host.is_empty() {
            node.transport.host = Some(h.host.join(","));
        }
        if h.path.is_some() {
            node.transport.path = h.path.clone();
        }
    }
    if let Some(g) = &streams.grpc_settings {
        node.transport.kind = TransportKind::Grpc;
        node.transport.service_name = g.service_name.clone().or_else(|| g.authority.clone());
        if g.multi_mode == Some(true) {
            node.transport.mode = Some("multi".into());
        }
        if node.transport.host.is_none() {
            node.transport.host = g.authority.clone();
        }
    }
    if let Some(tcp) = &streams.tcp_settings {
        let mut raw = serde_json::to_value(tcp).ok();
        if let Some(header) = &tcp.header {
            if header.kind.eq_ignore_ascii_case("http") {
                // surface the masquerade where the other transports keep it
                node.transport.header_type = Some("http".into());
                if let Some(path) = tcp_request_path(header) {
                    node.transport.path = Some(path);
                }
                if let Some(host) = tcp_request_host(header) {
                    node.transport.host = Some(host);
                }
            } else if !header.kind.is_empty() {
                node.transport.header_type = Some(header.kind.clone());
            }
        }
        if let Some(seed) = &tcp.seed {
            node.transport.seed = Some(seed.clone());
        }
        if tcp.accept_proxy_protocol == Some(true) {
            if let Some(Value::Object(map)) = raw.as_mut() {
                map.insert("acceptProxyProtocol".into(), Value::Bool(true));
            }
        }
        node.transport.raw = raw.and_then(|v| serde_json::to_string(&v).ok());
    }
    if let Some(k) = &streams.kcp_settings {
        node.transport.kind = TransportKind::Kcp;
        node.transport.header_type = k.header_type.clone();
        node.transport.seed = k.seed.clone();
    }
    if let Some(q) = &streams.quic_settings {
        node.transport.kind = TransportKind::Quic;
        node.transport.header_type = q.header_type.clone();
        node.transport.seed = q.key.clone();
    }
    if node.protocol == Protocol::Hysteria2 {
        if let Some(h) = &streams.hysteria_settings {
            if node.password.is_none() {
                node.password = h
                    .auth
                    .as_deref()
                    .map(str::trim)
                    .filter(|a| !a.is_empty())
                    .map(str::to_string);
            }
        }
        for mask in streams.final_mask.as_ref().map(|m| m.udp.as_slice()).unwrap_or(&[]) {
            match mask.kind.to_ascii_lowercase().as_str() {
                "salamander" => {
                    node.obfs = Some("salamander".into());
                    if let Some(pw) = mask.settings.get("password").and_then(Value::as_str) {
                        node.extra.insert("obfs-password".into(), pw.to_string());
                    }
                }
                "udphop" => {
                    if let Some(ports) = mask.settings.get("remotePorts") {
                        if let Some(text) = ports_text(ports) {
                            node.port_hopping = Some(text);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// A `PortList`/port value as the share-link spelling (`443`, `1000-2000`).
fn ports_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().filter_map(ports_text).collect();
            (!parts.is_empty()).then(|| parts.join(","))
        }
        _ => None,
    }
}

/// Flatten `xhttpSettings.extra` into string pairs for [`Transport::extra`],
/// which is what links and other formats can carry.
fn xhttp_extra_to_strings(extra: &Value) -> std::collections::BTreeMap<String, String> {
    match extra {
        Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some((k.clone(), s.clone())),
                Value::Null => None,
                other => Some((k.clone(), other.to_string())),
            })
            .collect(),
        _ => Default::default(),
    }
}

/// Rebuild the `xhttpSettings.extra` object.
///
/// The verbatim JSON from [`crate::node::Transport::raw`] wins, because it keeps
/// `"1000000"` a string instead of turning it into a number and keeps `xmux` an
/// object. The flattened string map is only a fallback for nodes that were
/// built from a share link, where that is all the information there is.
fn xhttp_extra_object(t: &Transport) -> Value {
    if let Some(raw) = &t.raw {
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            return parsed;
        }
    }
    // Nodes built from a share link only have the flattened strings; scalars
    // are retyped for the fields where XRay expects a non-string.
    let mut map = serde_json::Map::new();
    for (k, v) in &t.extra {
        let parsed = match v.as_str() {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            s => Value::String(s.to_string()),
        };
        map.insert(k.clone(), parsed);
    }
    Value::Object(map)
}

/// First path of a tcp-http masquerade request.
fn tcp_request_path(header: &TcpHeader) -> Option<String> {
    let request = header.request.as_ref()?;
    let paths = request.get("path")?;
    match paths {
        Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_string),
        Value::String(one) => Some(one.clone()),
        _ => None,
    }
}

/// `Host` header of a tcp-http masquerade request.
fn tcp_request_host(header: &TcpHeader) -> Option<String> {
    let request = header.request.as_ref()?;
    let hosts = request.get("headers")?.get("Host")?;
    match hosts {
        Value::String(one) => Some(one.clone()),
        Value::Array(items) => items.first().and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn protocol_is_tls_only(node: &Node) -> bool {
    matches!(
        node.protocol,
        Protocol::Trojan | Protocol::Hysteria | Protocol::Hysteria2 | Protocol::Tuic
    )
}

// ---------------------------------------------------------------- rendering

/// Build a single-node XRay config (freedom outbound included).
pub fn render(nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<String> {
    if nodes.is_empty() {
        return Err(Error::MalformedLink("no nodes to render".into()));
    }
    let value = export_config(nodes, balancer)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

/// Build the config object itself, so callers can post-process it.
pub fn export_config(nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<Value> {
    // When the caller supplied balancer members they are the tags; otherwise
    // fall back to labels. Either way the two can never disagree.
    let labels: Vec<String> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            node.label
                .clone()
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| format!("{}-{}", node.protocol.as_str(), i))
        })
        .collect();
    let tags = match balancer {
        Some(spec) if !spec.members.is_empty() => spec.members.clone(),
        _ => labels,
    };
    export_config_tagged(nodes, &tags, balancer)
}

/// Same, with caller-supplied tags.
///
/// Tag choice matters: XRay resolves a balancer `selector` with
/// `strings.HasPrefix`, so one tag being a prefix of another silently pulls the
/// extra outbounds into the balancer. Callers that emit several partial
/// balancers must supply collision-free tags — see
/// [`crate::balancer::plan::TagScheme`].
/// Local SOCKS and HTTP entry points, the pair every desktop client expects.
///
/// A subscription profile is normally handed to a client that adds its own
/// inbounds, which is why the exporter does not emit them by default. A config
/// meant to be run on its own needs them, or the machine has nothing to point
/// at the balancer.
pub fn default_inbounds() -> Value {
    json!([
        {
            "tag": "socks",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
        },
        {
            "tag": "http",
            "listen": "127.0.0.1",
            "port": 10809,
            "protocol": "http",
            "settings": { "udp": true },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
        }
    ])
}

pub fn export_config_tagged(
    nodes: &[Node],
    tags: &[String],
    balancer: Option<&BalancerSpec>,
) -> Result<Value> {
    if tags.len() != nodes.len() {
        return Err(Error::Balancer(format!(
            "got {} tags for {} nodes",
            tags.len(),
            nodes.len()
        )));
    }
    // A balancer's `members` *are* the tags it selects, so they must be the
    // same strings used for the outbounds — otherwise the selector points at
    // nothing and XRay silently balances an empty candidate list.
    if let Some(spec) = balancer {
        if !spec.members.is_empty() {
            for tag in &spec.members {
                if !tags.iter().any(|t| t == tag) {
                    return Err(Error::Balancer(format!(
                        "balancer `{}` selects `{tag}`, which is not an outbound tag ({tags:?})",
                        spec.name
                    )));
                }
            }
        }
    }
    let mut outbounds: Vec<Value> = Vec::new();

    for (node, tag) in nodes.iter().zip(tags) {
        let mut ob = outbound_body(node)?;
        if let Value::Object(map) = &mut ob {
            map.insert("tag".into(), json!(tag));
        }
        outbounds.push(ob);
    }

    let mut config = json!({
        "log": { "loglevel": "warning" },
        "outbounds": outbounds,
    });

    if let Some(spec) = balancer {
        let members = balancer_members(nodes, spec);
        config["outbounds"] = Value::Array(outbounds);
        // XRay declares balancers inside `routing`; a rule may only point at a
        // balancer declared there, and a stray top-level `balancers` is ignored
        // by XRay and dropped entirely by clients that parse a fixed schema.
        // No inboundTag => the rule matches every inbound, so the generated
        // config works even though we do not create inbounds.
        config["routing"] = routing_block(
            vec![balancer_object(spec, &members, nodes.len())],
            json!({ "type": "field", "balancerTag": spec.name }),
        );
        config["outbounds"].as_array_mut().unwrap().push(json!({
            "tag": "direct",
            "protocol": "freedom",
            "settings": { "domainStrategy": "UseIP" }
        }));
    } else {
        config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "tag": "direct", "protocol": "freedom" }));
    }

    Ok(config)
}

/// Build `routing.balancers` out of every balancer a plan declares.
///
/// The plan hands back plain balancer objects; XRay only accepts them nested
/// under `routing`, and that is also the only place clients read them from.
pub fn routing_block(balancers: Vec<Value>, rule: Value) -> Value {
    let mut rule = rule;
    // XRay refuses to start on a routing rule carrying no matching field —
    // "this rule has no effective fields" — even when the rule has a target. A
    // bare `{balancerTag: …}` is the natural way to say "send everything here",
    // and it makes the whole config unusable, so the network matcher is added to
    // give the rule something to match: every connection a client sends is
    // either TCP or UDP.
    if rule.get("domain").is_none()
        && rule.get("ip").is_none()
        && rule.get("port").is_none()
        && rule.get("network").is_none()
        && rule.get("inboundTag").is_none()
        && rule.get("protocol").is_none()
        && rule.get("process").is_none()
        && rule.get("source").is_none()
        && rule.get("sourcePort").is_none()
        && rule.get("user").is_none()
    {
        rule["network"] = json!("tcp,udp");
    }
    json!({
        "domainStrategy": "AsIs",
        "balancers": balancers,
        "rules": [rule]
    })
}

/// Default probe interval for a burst observatory, in seconds.
///
/// Short, and not for performance. A burst observatory schedules each probe at a
/// random point inside `interval * sampling`, so that product is the longest it
/// can take before the *first* measurement exists. A latency strategy has nothing
/// to rank on until then, and a client shows every node as having no latency —
/// which looks exactly like a broken subscription. At 10s x 2 that is twenty
/// seconds; at 300s x 2 it is ten minutes.
pub const DEFAULT_BURST_INTERVAL: u64 = 10;

/// Build a `burstObservatory` covering `tags`.
///
/// `burstObservatory` does not take `probeUrl`/`probeInterval` — those belong to
/// the plain `observatory`. A burst one spells the same settings `pingConfig`,
/// and anything else is silently ignored, which leaves `leastPing` ranking on
/// measurements nobody takes.
pub fn burst_observatory(tags: &[String], url: &str, interval: u64) -> Value {
    // XRay clamps a burst interval below 10s to 10s anyway; ask for it directly
    // instead of publishing a number the core will not honour.
    let interval = interval.max(10);
    json!({
        "subjectSelector": tags,
        "pingConfig": {
            "destination": url,
            "connectivity": url,
            "interval": format!("{interval}s"),
            "sampling": 2,
            "timeout": "5s"
        }
    })
}

/// Name a config the way clients read it.
///
/// `remarks` is the field subscriptions are titled by (`remark` alone leaves the
/// profile unnamed in the client's list); `remark` is kept because it is what
/// this library has always written and other tooling looks for it.
pub fn set_name(config: &mut Value, name: &str) {
    config["remarks"] = json!(name);
    config["remark"] = json!(name);
}

/// Build one `routing.balancers[]` entry.
///
/// `fallbackTag` is always set: XRay needs it for `leastPing`/`leastLoad` in
/// practice, and without it a balancer whose members all die has nowhere to go.
pub fn balancer_object(spec: &BalancerSpec, members: &[String], total: usize) -> Value {
    let fallback = spec.fallback.clone().or_else(|| members.first().cloned());
    let mut strategy = json!({ "type": spec.kind.xray_name() });
    if spec.url.is_some() || spec.interval.is_some() {
        strategy["settings"] = json!({
            "probeURL": spec.url.clone().unwrap_or_else(|| "https://www.gstatic.com/generate_204".into()),
            "probeInterval": format!("{}s", spec.interval.unwrap_or(300)),
        });
    } else if matches!(spec.kind, BalancerKind::Random) {
        strategy["settings"] = json!({ "expectedLength": members.len() });
    }
    let _ = total;
    json!({
        "tag": spec.name,
        "selector": members,
        "fallbackTag": fallback,
        "strategy": strategy,
    })
}

/// Build `tcpSettings` from what the node carries, preferring the verbatim copy
/// (it holds the request line, method and every path, which do not fit into the
/// link format).
fn tcp_settings_object(t: &Transport) -> Option<Value> {
    if let Some(raw) = &t.raw {
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            if parsed.get("header").is_some() || parsed.get("acceptProxyProtocol").is_some() {
                return Some(parsed);
            }
        }
    }
    let header_type = t.header_type.as_deref()?;
    if header_type.is_empty() || header_type == "none" {
        return None;
    }
    let mut request = serde_json::Map::new();
    request.insert("method".into(), json!("GET"));
    request.insert(
        "path".into(),
        json!([t.path.clone().unwrap_or_else(|| "/".into())]),
    );
    let mut headers = serde_json::Map::new();
    headers.insert(
        "Host".into(),
        json!([t.host.clone().unwrap_or_default()]),
    );
    request.insert("headers".into(), Value::Object(headers));
    Some(json!({
        "header": { "type": header_type, "request": Value::Object(request) }
    }))
}

/// One outbound object with an explicit tag, for assembling configs by hand.
pub fn outbound_for(node: &Node, tag: &str) -> Value {
    let mut ob = outbound_body(node).unwrap_or_else(|_| json!({}));
    if let Value::Object(map) = &mut ob {
        map.insert("tag".into(), json!(tag));
    }
    ob
}

pub fn balancer_members(nodes: &[Node], spec: &BalancerSpec) -> Vec<String> {
    if spec.members.is_empty() {
        nodes
            .iter()
            .enumerate()
            .map(|(i, n)| n.display_name(i))
            .collect()
    } else {
        spec.members.clone()
    }
}

fn outbound_body(node: &Node) -> Result<Value> {
    let (protocol, settings) = match node.protocol {
        Protocol::Vless | Protocol::Vmess => {
            let mut user = serde_json::Map::new();
            user.insert("id".into(), json!(node.uuid.clone().unwrap_or_default()));
            user.insert(
                "encryption".into(),
                json!(node.extra.get("encryption").cloned().unwrap_or_else(|| "none".into())),
            );
            if node.protocol == Protocol::Vless {
                // only write a flow when there is one: `"flow": ""` is noise in
                // the config and in every diff against it
                if let Some(flow) = node.flow.as_deref().filter(|f| !f.is_empty()) {
                    user.insert("flow".into(), json!(flow));
                }
            } else {
                user.insert("alterId".into(), json!(0));
                user.insert("security".into(), json!(node.extra.get("scy").cloned().unwrap_or_else(|| "auto".into())));
            }
            (
                node.protocol.as_str().to_string(),
                json!({ "vnext": [{
                    "address": node.address,
                    "port": node.port,
                    "users": [Value::Object(user)],
                }]}),
            )
        }
        Protocol::Trojan => (
            "trojan".into(),
            json!({ "servers": [{
                "address": node.address,
                "port": node.port,
                "password": node.password.clone().unwrap_or_default(),
            }]}),
        ),
        Protocol::Hysteria2 => (
            // XRay's outbound is `hysteria`; version 2 makes it Hysteria2. The
            // credentials live in `streamSettings.hysteriaSettings`, not here.
            "hysteria".into(),
            json!({
                "address": node.address,
                "port": node.port,
                "version": 2,
            }),
        ),
        Protocol::Hysteria | Protocol::Tuic | Protocol::Anytls => {
            let mut server = serde_json::Map::new();
            server.insert("address".into(), json!(node.address));
            server.insert("port".into(), json!(node.port));
            if let Some(pw) = &node.password {
                server.insert("password".into(), json!(pw));
            }
            if let Some(uuid) = &node.uuid {
                server.insert("uuid".into(), json!(uuid));
            }
            if let Some(hop) = &node.port_hopping {
                server.insert("ports".into(), json!(hop));
            }
            if let Some(obfs) = &node.obfs {
                server.insert("obfs".into(), json!(obfs));
            }
            (
                node.protocol.as_str().to_string(),
                json!({ "servers": [Value::Object(server)] }),
            )
        }
        Protocol::Socks | Protocol::Http => (
            node.protocol.as_str().to_string(),
            json!({ "servers": [{
                "address": node.address,
                "port": node.port,
            }]}),
        ),
        Protocol::Shadowsocks => (
            "shadowsocks".into(),
            json!({ "servers": [{
                "address": node.address,
                "port": node.port,
                "method": node.method.clone().unwrap_or_default(),
                "password": node.password.clone().unwrap_or_default(),
            }]}),
        ),
        Protocol::Wireguard => return Err(Error::UnsupportedProtocol("wireguard".into())),
    };

    Ok(json!({
        "protocol": protocol,
        "settings": settings,
        "streamSettings": stream_settings(node),
    }))
}

pub fn stream_settings(node: &Node) -> Value {
    let mut stream = serde_json::Map::new();
    let hysteria2 = node.protocol == Protocol::Hysteria2;
    if hysteria2 {
        stream.insert("network".into(), json!("hysteria"));
    } else if node.transport.kind != TransportKind::Tcp {
        stream.insert(
            "network".into(),
            json!(node.transport.kind.as_str()),
        );
    }
    stream.insert("security".into(), json!(node.security.as_str()));

    if node.security == Security::Reality {
        let mut reality = serde_json::Map::new();
        reality.insert("serverName".into(), json!(node.effective_sni().unwrap_or_default()));
        reality.insert("fingerprint".into(), json!(node.fingerprint.clone().unwrap_or_else(|| "chrome".into())));
        if let Some(pb) = &node.public_key {
            reality.insert("publicKey".into(), json!(pb));
        }
        if let Some(sid) = &node.short_id {
            reality.insert("shortId".into(), json!(sid));
        }
        if let Some(spx) = &node.spider_x {
            reality.insert("spiderX".into(), json!(spx));
        }
        stream.insert("realitySettings".into(), Value::Object(reality));
    } else if node.security != Security::None {
        let mut tls = serde_json::Map::new();
        tls.insert(
            "serverName".into(),
            json!(node.effective_sni().unwrap_or_default()),
        );
        // Hysteria2 defaults to h3 inside XRay when ALPN is empty. Spelling it
        // out here would make the same node hash differently depending on
        // whether it came from a link or from an XRay config, and two rows for
        // one server is worse than relying on the default.
        if !node.alpn.is_empty() {
            tls.insert("alpn".into(), json!(node.alpn));
        }
        if let Some(fp) = &node.fingerprint {
            tls.insert("fingerprint".into(), json!(fp));
        }
        if node.allow_insecure {
            tls.insert("allowInsecure".into(), json!(true));
        }
        stream.insert("tlsSettings".into(), Value::Object(tls));
    }

    if hysteria2 {
        let mut hysteria = serde_json::Map::new();
        hysteria.insert("version".into(), json!(2));
        if let Some(password) = node.password.as_deref().filter(|p| !p.is_empty()) {
            hysteria.insert("auth".into(), json!(password));
        }
        stream.insert("hysteriaSettings".into(), Value::Object(hysteria));

        let mut masks: Vec<Value> = Vec::new();
        if node
            .obfs
            .as_deref()
            .map(|o| o.eq_ignore_ascii_case("salamander"))
            .unwrap_or(false)
        {
            masks.push(json!({
                "type": "salamander",
                "settings": {
                    "password": node.extra.get("obfs-password").cloned().unwrap_or_default(),
                },
            }));
        }
        if let Some(ports) = &node.port_hopping {
            masks.push(json!({
                "type": "udphop",
                "settings": { "remotePorts": ports },
            }));
        }
        if !masks.is_empty() {
            stream.insert("finalmask".into(), json!({ "udp": masks }));
        }
    }

    match node.transport.kind {
        TransportKind::Ws => {
            let mut ws = serde_json::Map::new();
            ws.insert(
                "path".into(),
                json!(node.transport.path.clone().unwrap_or_else(|| "/".into())),
            );
            if let Some(host) = &node.transport.host {
                ws.insert("headers".into(), json!({ "Host": host }));
            }
            stream.insert("wsSettings".into(), Value::Object(ws));
        }
        TransportKind::Httpupgrade => {
            let mut hu = serde_json::Map::new();
            hu.insert("path".into(), json!(node.transport.path.clone().unwrap_or_else(|| "/".into())));
            if let Some(host) = &node.transport.host {
                hu.insert("host".into(), json!(host));
            }
            stream.insert("httpupgradeSettings".into(), Value::Object(hu));
        }
        TransportKind::Tcp if !hysteria2 => {
            // only when there is something to say: a plain tcp node needs no
            // tcpSettings block at all
            if let Some(raw) = tcp_settings_object(&node.transport) {
                stream.insert("tcpSettings".into(), raw);
            }
        }
        TransportKind::Xhttp => {
            let mut x = xhttp_extra_object(&node.transport);
            if !x.is_object() {
                x = Value::Object(serde_json::Map::new());
            }
            // host/path/mode always win, mirroring XRay's own precedence.
            x["path"] = json!(node.transport.path.clone().unwrap_or_else(|| "/".into()));
            if let Some(host) = &node.transport.host {
                x["host"] = json!(host);
            }
            x["mode"] = json!(node.transport.mode.clone().unwrap_or_else(|| "auto".into()));
            stream.insert("xhttpSettings".into(), x);
        }
        TransportKind::Grpc => {
            let mut g = serde_json::Map::new();
            g.insert(
                "serviceName".into(),
                json!(node.transport.service_name.clone().unwrap_or_default()),
            );
            g.insert("multiMode".into(), json!(node.transport.mode.as_deref() == Some("multi")));
            if let Some(auth) = &node.transport.host {
                g.insert("authority".into(), json!(auth));
            }
            stream.insert("grpcSettings".into(), Value::Object(g));
        }
        TransportKind::Kcp => {
            let mut k = serde_json::Map::new();
            k.insert(
                "headerType".into(),
                json!(node.transport.header_type.clone().unwrap_or_else(|| "none".into())),
            );
            if let Some(seed) = &node.transport.seed {
                k.insert("seed".into(), json!(seed));
            }
            stream.insert("kcpSettings".into(), Value::Object(k));
        }
        TransportKind::Quic => {
            let mut q = serde_json::Map::new();
            q.insert("security".into(), json!(node.transport.header_type.clone().unwrap_or_else(|| "none".into())));
            if let Some(key) = &node.transport.seed {
                q.insert("key".into(), json!(key));
            }
            stream.insert("quicSettings".into(), Value::Object(q));
        }
        _ => {}
    }

    Value::Object(stream)
}

/// Concatenated link list of every outbound in a config ("decompose").
pub fn decompose(bundle: &Bundle) -> Result<String> {
    crate::links::render_all(&bundle.nodes)
}

pub fn host_list(raw: &str) -> Vec<String> {
    split_list(raw)
}
