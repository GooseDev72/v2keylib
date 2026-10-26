//! mihomo (Clash.Meta) YAML configuration.
//!
//! ```yaml
//! proxies:
//!   - name: a
//!     type: vless
//!     server: 1.2.3.4
//!     port: 443
//!     uuid: ...
//!     network: ws
//!     tls: true
//!     servername: cdn.example.com
//!     ws-opts: { path: /ws, headers: { Host: cdn.example.com } }
//! proxy-groups:
//!   - name: auto
//!     type: url-test
//!     proxies: [a, b]
//! ```

use serde::{Deserialize, Serialize};
use serde_yaml::Value;

use crate::config::{BalancerKind, BalancerSpec, Bundle, Group};
use crate::error::{Error, Result};
use crate::node::{Node, Protocol, Security, TransportKind};
use crate::util::split_list;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MihomoConfig {
    #[serde(default, rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    pub mixed_port: Option<u16>,
    #[serde(default, rename = "allow-lan", skip_serializing_if = "Option::is_none")]
    pub allow_lan: Option<bool>,
    #[serde(default, rename = "mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<MihomoProxy>,
    #[serde(default, rename = "proxy-groups", skip_serializing_if = "Vec::is_empty")]
    pub proxy_groups: Vec<ProxyGroup>,
    #[serde(default, rename = "proxy-providers", skip_serializing_if = "Option::is_none")]
    pub proxy_providers: Option<Value>,
    #[serde(default, rename = "rule-providers", skip_serializing_if = "Option::is_none")]
    pub rule_providers: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxies: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<u32>,
    #[serde(default, rename = "use", skip_serializing_if = "Vec::is_empty")]
    pub use_providers: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MihomoProxy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, rename = "type", skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(default, rename = "client-fingerprint", skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub servername: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, rename = "skip-cert-verify", skip_serializing_if = "Option::is_none")]
    pub skip_cert_verify: Option<bool>,
    #[serde(default, rename = "tls-fingerprint", skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, rename = "ws-opts", skip_serializing_if = "Option::is_none")]
    pub ws_opts: Option<WsOpts>,
    #[serde(default, rename = "ws-path", skip_serializing_if = "Option::is_none")]
    pub ws_path: Option<String>,
    #[serde(
        default,
        rename = "ws-headers",
        skip_serializing_if = "Option::is_none"
    )]
    pub ws_headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, rename = "h2-opts", skip_serializing_if = "Option::is_none")]
    pub h2_opts: Option<GenericOpts>,
    #[serde(
        default,
        rename = "http-opts",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_opts: Option<GenericOpts>,
    #[serde(default, rename = "grpc-opts", skip_serializing_if = "Option::is_none")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(
        default,
        rename = "reality-opts",
        skip_serializing_if = "Option::is_none"
    )]
    pub reality_opts: Option<RealityOpts>,
    #[serde(default, rename = "http-upgrade-opts", skip_serializing_if = "Option::is_none")]
    pub http_upgrade_opts: Option<GenericOpts>,
    #[serde(default, rename = "xhttp-opts", skip_serializing_if = "Option::is_none")]
    pub xhttp_opts: Option<GenericOpts>,
    #[serde(default, rename = "headers", skip_serializing_if = "Option::is_none")]
    pub headers: Option<GenericOpts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, rename = "obfs-password", skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, rename = "hop-interval", skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, rename = "congestion-controller", skip_serializing_if = "Option::is_none")]
    pub congestion_controller: Option<String>,
    #[serde(default, rename = "udp-relay-mode", skip_serializing_if = "Option::is_none")]
    pub udp_relay_mode: Option<String>,
    #[serde(default, rename = "packet-encoding", skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WsOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, rename = "max-early-data", skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<i64>,
    #[serde(
        default,
        rename = "early-data-header-name",
        skip_serializing_if = "Option::is_none"
    )]
    pub early_data_header_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GrpcOpts {
    #[serde(default, rename = "grpc-service-name", skip_serializing_if = "Option::is_none")]
    pub grpc_service_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealityOpts {
    #[serde(default, rename = "public-key", skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, rename = "short-id", skip_serializing_if = "Option::is_none")]
    pub short_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenericOpts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default, rename = "host", skip_serializing_if = "Option::is_none")]
    pub host: Option<Value>,
}

// ---------------------------------------------------------------- parsing

pub fn parse(input: &str) -> Result<Bundle> {
    let cfg: MihomoConfig = serde_yaml::from_str(input)?;
    let mut bundle = Bundle::default();

    for proxy in &cfg.proxies {
        if let Some(node) = proxy_to_node(proxy)? {
            bundle.nodes.push(node);
        }
    }
    for group in &cfg.proxy_groups {
        bundle.groups.push(Group {
            name: group.name.clone(),
            kind: BalancerKind::parse(&group.kind).unwrap_or(BalancerKind::Selector),
            members: group.proxies.clone(),
            fallback: group
                .proxies
                .first()
                .filter(|_| group.kind == "fallback")
                .cloned(),
            url: group.url.clone(),
            interval: group.interval,
        });
    }

    Ok(bundle)
}

pub fn proxy_to_node(proxy: &MihomoProxy) -> Result<Option<Node>> {
    let protocol = match proxy.kind.to_ascii_lowercase().as_str() {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "hysteria" => Protocol::Hysteria,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        "ss" | "shadowsocks" => Protocol::Shadowsocks,
        "tuic" => Protocol::Tuic,
        "socks5" | "socks" => Protocol::Socks,
        "http" | "https" => Protocol::Http,
        "anytls" => Protocol::Anytls,
        "wireguard" => Protocol::Wireguard,
        _ => return Ok(None),
    };
    let address = proxy
        .server
        .clone()
        .ok_or(Error::MissingField("server"))?;
    let port = proxy.port.ok_or(Error::MissingField("port"))?;
    let mut node = Node::new(protocol, address, port);
    node.uuid = proxy.uuid.clone();
    node.password = proxy.password.clone();
    node.method = proxy.cipher.clone();
    node.flow = proxy.flow.clone();
    node.label = proxy.name.clone();
    node.sni = proxy.servername.clone().or_else(|| proxy.sni.clone());
    node.alpn = proxy.alpn.clone();
    node.fingerprint = proxy
        .client_fingerprint
        .clone()
        .or_else(|| proxy.tls_fingerprint.clone());
    node.allow_insecure = proxy.skip_cert_verify.unwrap_or(false);
    node.port_hopping = proxy.ports.clone();
    node.up_mbps = proxy.up.as_deref().and_then(parse_bandwidth);
    node.down_mbps = proxy.down.as_deref().and_then(parse_bandwidth);
    if proxy.obfs.is_some() {
        node.obfs = proxy.obfs.clone();
    }
    if let Some(pw) = &proxy.obfs_password {
        node.extra.insert("obfs-password".into(), pw.clone());
    }
    if let Some(cc) = &proxy.congestion_controller {
        node.extra.insert("congestion_control".into(), cc.clone());
    }

    // TLS
    match proxy.kind.to_ascii_lowercase().as_str() {
        "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls" => {
            node.security = Security::Tls;
        }
        _ => {
            node.security = match (proxy.tls, proxy.tls_fingerprint.as_deref()) {
                (Some(true), Some("chrome")) => Security::Tls,
                (Some(true), _) => Security::Tls,
                _ => Security::None,
            };
        }
    }
    if proxy.reality_opts.is_some() {
        node.security = Security::Reality;
        if let Some(r) = &proxy.reality_opts {
            node.public_key = r.public_key.clone();
            node.short_id = r.short_id.clone();
        }
    }

    // network / transport
    let network = proxy.network.clone().unwrap_or_else(|| "tcp".into());
    node.transport.kind = TransportKind::parse(&network);
    if let Some(ws) = &proxy.ws_opts {
        node.transport.kind = TransportKind::Ws;
        node.transport.path = ws.path.clone();
        node.transport.host = ws.headers.as_ref().and_then(host_header);
    }
    if proxy.ws_path.is_some() {
        node.transport.path = proxy.ws_path.clone();
        node.transport.host = proxy.ws_headers.as_ref().and_then(host_header);
    }
    if let Some(h2) = &proxy.h2_opts {
        node.transport.kind = TransportKind::H2;
        node.transport.path = h2.path.clone();
        node.transport.host = host_from_value(h2.host.as_ref()).or_else(|| h2.headers.as_ref().and_then(host_header));
    }
    if let Some(h) = &proxy.http_opts {
        node.transport.kind = TransportKind::Http;
        node.transport.path = h.path.clone();
        node.transport.host = host_from_value(h.host.as_ref()).or_else(|| h.headers.as_ref().and_then(host_header));
    }
    if let Some(hu) = &proxy.http_upgrade_opts {
        node.transport.kind = TransportKind::Httpupgrade;
        node.transport.path = hu.path.clone();
        node.transport.host = host_from_value(hu.host.as_ref()).or_else(|| hu.headers.as_ref().and_then(host_header));
    }
    if let Some(x) = &proxy.xhttp_opts {
        node.transport.kind = TransportKind::Xhttp;
        node.transport.path = x.path.clone();
        node.transport.host = host_from_value(x.host.as_ref()).or_else(|| x.headers.as_ref().and_then(host_header));
    }
    if let Some(g) = &proxy.grpc_opts {
        node.transport.kind = TransportKind::Grpc;
        node.transport.service_name = g.grpc_service_name.clone();
    }
    if let Some(h) = &proxy.headers {
        node.transport.host = h.headers.as_ref().and_then(host_header).or(node.transport.host);
    }

    Ok(Some(node))
}

fn host_header(map: &std::collections::BTreeMap<String, String>) -> Option<String> {
    map.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
}

fn host_from_value(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Sequence(seq) => Some(
            seq.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    }
}

fn parse_bandwidth(raw: &str) -> Option<u32> {
    let digits: String = raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

// ---------------------------------------------------------------- rendering

pub fn render(nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<String> {
    if nodes.is_empty() {
        return Err(Error::MalformedLink("no nodes to render".into()));
    }
    let mut proxies: Vec<MihomoProxy> = Vec::new();
    // clash/mihomo address proxies by name, so these have to be unique
    let names = Node::unique_names(nodes);

    for (node, name) in nodes.iter().zip(names.iter()) {
        let mut proxy = node_to_proxy(node, name)?;
        proxy.name = Some(name.clone());
        proxies.push(proxy);
    }

    let mut cfg = MihomoConfig {
        mixed_port: Some(7890),
        allow_lan: Some(false),
        mode: Some("rule".into()),
        proxies,
        ..Default::default()
    };

    if let Some(spec) = balancer {
        let members = super::xray::balancer_members(nodes, spec);
        let mut group = ProxyGroup {
            name: spec.name.clone(),
            kind: spec.kind.mihomo_name().to_string(),
            proxies: members,
            ..Default::default()
        };
        if matches!(
            spec.kind,
            BalancerKind::UrlTest | BalancerKind::LeastPing | BalancerKind::Fallback
        ) {
            group.url = Some(
                spec.url
                    .clone()
                    .unwrap_or_else(|| "https://www.gstatic.com/generate_204".into()),
            );
            group.interval = Some(spec.interval.unwrap_or(300));
        }
        if let Some(tol) = spec.tolerance {
            group.tolerance = Some(tol);
        }
        group.strategy = spec
            .strategy
            .clone()
            .or_else(|| match spec.kind {
                BalancerKind::RoundRobin | BalancerKind::LeastLoad => {
                    Some("round-robin".to_string())
                }
                _ => None,
            });
        cfg.proxy_groups = vec![group];
        cfg.rules = vec![serde_yaml::from_str(&format!("{},{}", "MATCH,{}", spec.name)).unwrap()];
    } else {
        cfg.proxy_groups = vec![ProxyGroup {
            name: "PROXY".into(),
            kind: "select".into(),
            proxies: names,
            ..Default::default()
        }];
        cfg.rules = vec![serde_yaml::from_str("MATCH,PROXY").unwrap()];
    }

    let yaml = serde_yaml::to_string(&cfg)?;
    Ok(yaml)
}

/// Render a whole bundle: every balancer in it becomes a proxy-group.
///
/// [`render`] writes one group, because that is what a generated config needs.
/// A bundle parsed from somewhere else — an XRay config with a group per
/// country — has as many groups as it has, and folding them into one would
/// throw away the structure the subscription is built around.
///
/// Group members are tags, and the proxies are named by [`Node::unique_names`],
/// so the tags are resolved through the nodes instead of being trusted to match.
/// A member that names no node (a `direct` outbound, a tier that came out empty)
/// is dropped rather than left pointing at nothing.
pub fn from_bundle(bundle: &Bundle) -> Result<String> {
    if bundle.nodes.is_empty() {
        return Err(Error::MalformedLink("no nodes to render".into()));
    }
    let names = Node::unique_names(&bundle.nodes);
    let by_tag: std::collections::HashMap<&str, &str> = bundle
        .nodes
        .iter()
        .zip(names.iter())
        .filter_map(|(node, name)| node.label.as_deref().map(|tag| (tag, name.as_str())))
        .collect();

    let mut proxies = Vec::with_capacity(bundle.nodes.len());
    for (node, name) in bundle.nodes.iter().zip(names.iter()) {
        let mut proxy = node_to_proxy(node, name)?;
        proxy.name = Some(name.clone());
        proxies.push(proxy);
    }

    let mut proxy_groups = Vec::new();
    for group in &bundle.groups {
        let members: Vec<String> = group
            .members
            .iter()
            .filter_map(|tag| by_tag.get(tag.as_str()).map(|name| name.to_string()))
            .collect();
        if members.is_empty() {
            continue;
        }
        let mut out = ProxyGroup {
            name: group.name.clone(),
            kind: group.kind.mihomo_name().to_string(),
            proxies: members,
            ..Default::default()
        };
        if matches!(
            group.kind,
            BalancerKind::UrlTest | BalancerKind::LeastPing | BalancerKind::Fallback
        ) {
            out.url = Some(
                group
                    .url
                    .clone()
                    .unwrap_or_else(|| "https://www.gstatic.com/generate_204".into()),
            );
            out.interval = Some(group.interval.unwrap_or(300));
        }
        proxy_groups.push(out);
    }

    let entry = proxy_groups
        .first()
        .map(|g| g.name.clone())
        .unwrap_or_else(|| "DIRECT".into());
    let mut cfg = MihomoConfig {
        mixed_port: Some(7890),
        allow_lan: Some(false),
        mode: Some("rule".into()),
        proxies,
        proxy_groups,
        ..Default::default()
    };
    cfg.rules = vec![serde_yaml::from_str(&format!("MATCH,{entry}")).unwrap()];
    Ok(serde_yaml::to_string(&cfg)?)
}

pub fn node_to_proxy(node: &Node, _name: &str) -> Result<MihomoProxy> {
    let mut proxy = MihomoProxy {
        kind: mihomo_type(node.protocol)?.to_string(),
        server: Some(node.address.clone()),
        port: Some(node.port),
        ..Default::default()
    };

    match node.protocol {
        Protocol::Vless | Protocol::Vmess | Protocol::Anytls => {
            proxy.uuid = node.uuid.clone();
        }
        Protocol::Trojan => {
            proxy.password = node.password.clone();
        }
        Protocol::Hysteria | Protocol::Hysteria2 => {
            proxy.password = node.password.clone();
        }
        Protocol::Shadowsocks => {
            proxy.cipher = node.method.clone();
            proxy.password = node.password.clone();
        }
        Protocol::Socks | Protocol::Http => {
            proxy.version = Some("5".into());
        }
        Protocol::Tuic => {
            proxy.uuid = node.uuid.clone();
            proxy.password = node.password.clone();
            proxy.congestion_controller = node.extra.get("congestion_control").cloned();
        }
        Protocol::Wireguard => return Err(Error::UnsupportedProtocol("wireguard".into())),
    }

    if let Some(flow) = &node.flow {
        proxy.flow = Some(flow.clone());
    }
    if node.security != Security::None {
        proxy.tls = Some(true);
        if let Some(sni) = node.effective_sni() {
            proxy.servername = Some(sni);
        }
        if !node.alpn.is_empty() {
            proxy.alpn = node.alpn.clone();
        }
        if node.allow_insecure {
            proxy.skip_cert_verify = Some(true);
        }
    }
    if node.security == Security::Reality {
        proxy.reality_opts = Some(RealityOpts {
            public_key: node.public_key.clone(),
            short_id: node.short_id.clone(),
        });
        if let Some(fp) = &node.fingerprint {
            proxy.client_fingerprint = Some(fp.clone());
        }
    } else if let Some(fp) = &node.fingerprint {
        proxy.client_fingerprint = Some(fp.clone());
    }

    if let Some(hop) = &node.port_hopping {
        proxy.ports = Some(hop.clone());
    }
    if let Some(v) = node.up_mbps {
        proxy.up = Some(format!("{v}"));
    }
    if let Some(v) = node.down_mbps {
        proxy.down = Some(format!("{v}"));
    }
    if let Some(obfs) = &node.obfs {
        proxy.obfs = Some(obfs.clone());
        proxy.obfs_password = node.extra.get("obfs-password").cloned();
    }

    if node.transport.kind != TransportKind::Tcp {
        proxy.network = Some(node.transport.kind.as_str().to_string());
    }
    match node.transport.kind {
        TransportKind::Ws => {
            let mut headers = std::collections::BTreeMap::new();
            if let Some(host) = &node.transport.host {
                headers.insert("Host".to_string(), host.clone());
            }
            proxy.ws_opts = Some(WsOpts {
                path: node.transport.path.clone(),
                headers: (!headers.is_empty()).then_some(headers),
                ..Default::default()
            });
        }
        TransportKind::Grpc => {
            proxy.grpc_opts = Some(GrpcOpts {
                grpc_service_name: node.transport.service_name.clone(),
            });
        }
        TransportKind::H2 | TransportKind::Http | TransportKind::Httpupgrade | TransportKind::Xhttp => {
            let opts = GenericOpts {
                path: node.transport.path.clone(),
                headers: None,
                host: node.transport.host.as_ref().map(|h| {
                    if h.contains(',') {
                        Value::Sequence(
                            split_list(h)
                                .into_iter()
                                .map(Value::String)
                                .collect::<Vec<_>>(),
                        )
                    } else {
                        Value::String(h.clone())
                    }
                }),
            };
            match node.transport.kind {
                TransportKind::H2 => proxy.h2_opts = Some(opts),
                TransportKind::Http => proxy.http_opts = Some(opts),
                TransportKind::Httpupgrade => proxy.http_upgrade_opts = Some(opts),
                TransportKind::Xhttp => proxy.xhttp_opts = Some(opts),
                _ => {}
            }
        }
        _ => {}
    }

    Ok(proxy)
}

fn mihomo_type(protocol: Protocol) -> Result<&'static str> {
    Ok(match protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Trojan => "trojan",
        Protocol::Hysteria => "hysteria",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Shadowsocks => "ss",
        Protocol::Socks => "socks5",
        Protocol::Http => "http",
        Protocol::Tuic => "tuic",
        Protocol::Anytls => "anytls",
        Protocol::Wireguard => return Err(Error::UnsupportedProtocol("wireguard".into())),
    })
}

/// Flatten proxies into plain links.
pub fn decompose(bundle: &Bundle) -> Result<String> {
    crate::links::render_all(&bundle.nodes)
}
