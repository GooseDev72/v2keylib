//! sing-box JSON configuration.
//!
//! ```json
//! { "outbounds": [
//!     { "type": "vless", "tag": "a", "server": "1.2.3.4", "server_port": 443,
//!       "uuid": "...", "tls": { "enabled": true, "server_name": "..." },
//!       "transport": { "type": "ws", "path": "/", "headers": {"Host": "..."} } },
//!     { "type": "urltest", "tag": "auto", "outbounds": ["a", "b"] } ] }
//! ```
//!
//! Newer sing-box (1.11+) renamed `transport` to `v2ray_transport`; both are
//! accepted on input and `v2ray_transport` is emitted for `vless`/`vmess`.

use serde_json::{json, Map, Value};

use crate::config::{BalancerKind, BalancerSpec, Bundle, Group};
use crate::error::{Error, Result};
use crate::node::{Node, Protocol, Security, Transport, TransportKind};
use crate::util::split_list;

pub fn parse(input: &str) -> Result<Bundle> {
    let text = super::xray::strip_bom(input);
    let value: Value = serde_json::from_str(text)?;
    let root = value.as_object().ok_or(Error::Detection)?;

    let mut bundle = Bundle::default();
    let outbounds = root
        .get("outbounds")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let group_types = ["urltest", "selector", "random", "fallback", "loadbalance"];
    for ob in &outbounds {
        let kind = ob.get("type").and_then(Value::as_str).unwrap_or("");
        if !group_types.contains(&kind) {
            if let Some(node) = parse_outbound(ob)? {
                bundle.nodes.push(node);
            }
        }
    }
    for ob in &outbounds {
        let kind = ob.get("type").and_then(Value::as_str).unwrap_or("");
        if !group_types.contains(&kind) {
            continue;
        }
        let name = ob
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or(kind)
            .to_string();
        let members = ob
            .get("outbounds")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let interval = ob
            .get("interval")
            .and_then(Value::as_str)
            .and_then(parse_duration);
        bundle.groups.push(Group {
            name,
            kind: BalancerKind::parse(kind).unwrap_or(BalancerKind::UrlTest),
            members,
            fallback: None,
            url: ob.get("url").and_then(Value::as_str).map(str::to_string),
            interval,
        });
    }

    // Experimental outbound may hold nested groups (1.11+ `endpoints`).
    if let Some(ends) = root.get("endpoints").and_then(Value::as_array) {
        for ep in ends {
            let kind = ep.get("type").and_then(Value::as_str).unwrap_or("");
            if group_types.contains(&kind) {
                let name = ep
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or(kind)
                    .to_string();
                let members = ep
                    .get("outbounds")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                bundle.groups.push(Group {
                    name,
                    kind: BalancerKind::parse(kind).unwrap_or(BalancerKind::UrlTest),
                    members,
                    fallback: None,
                    url: ep.get("url").and_then(Value::as_str).map(str::to_string),
                    interval: ep.get("interval").and_then(Value::as_str).and_then(parse_duration),
                });
            }
        }
    }

    Ok(bundle)
}

/// `300s`, `5m`, `1h30m`, `42` -> seconds
pub fn parse_duration(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if let Ok(v) = raw.parse::<u64>() {
        return Some(v);
    }
    let mut total = 0u64;
    let mut num = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            num.push(ch);
            continue;
        }
        let value: u64 = num.parse().ok()?;
        num.clear();
        total += match ch {
            's' => value,
            'm' => value * 60,
            'h' => value * 3600,
            _ => return None,
        };
    }
    if !num.is_empty() {
        let value: u64 = num.parse().ok()?;
        total += value;
    }
    Some(total)
}

pub fn parse_outbound(ob: &Value) -> Result<Option<Node>> {
    let kind = ob.get("type").and_then(Value::as_str).unwrap_or("");
    let protocol = match kind {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "hysteria" => Protocol::Hysteria,
        "hysteria2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "shadowsocks" => Protocol::Shadowsocks,
        "socks" => Protocol::Socks,
        "http" => Protocol::Http,
        "anytls" => Protocol::Anytls,
        _ => return Ok(None),
    };
    let address = ob
        .get("server")
        .and_then(Value::as_str)
        .ok_or(Error::MissingField("server"))?
        .to_string();
    let port = ob
        .get("server_port")
        .and_then(Value::as_u64)
        .ok_or(Error::MissingField("server_port"))? as u16;

    let mut node = Node::new(protocol, address, port);
    node.uuid = ob
        .get("uuid")
        .or_else(|| ob.get("password"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if protocol == Protocol::Trojan || protocol == Protocol::Anytls {
        node.password = ob
            .get("password")
            .and_then(Value::as_str)
            .map(str::to_string);
    } else if protocol == Protocol::Hysteria2 || protocol == Protocol::Hysteria {
        node.password = ob
            .get("password")
            .or_else(|| ob.get("auth"))
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    if let Some(m) = ob.get("method").and_then(Value::as_str) {
        node.method = Some(m.to_string());
    }
    node.flow = ob
        .get("flow")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string);

    apply_tls(&mut node, ob.get("tls"));
    apply_transport(&mut node, ob);

    if let Some(hop) = ob
        .get("server_ports")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
                .join(",")
        })
        .filter(|s| !s.is_empty())
    {
        node.port_hopping = Some(hop);
    }
    if let Some(hop) = ob.get("hop_interval").and_then(Value::as_str) {
        node.extra.insert("hop_interval".into(), hop.to_string());
    }
    if let Some(v) = ob.get("up_mbps").and_then(Value::as_u64) {
        node.up_mbps = Some(v as u32);
    }
    if let Some(v) = ob.get("down_mbps").and_then(Value::as_u64) {
        node.down_mbps = Some(v as u32);
    }
    if let Some(v) = ob.get("obfs").and_then(Value::as_object) {
        node.obfs = v
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_string);
        if let Some(pw) = v.get("password").and_then(Value::as_str) {
            node.extra.insert("obfs-password".into(), pw.to_string());
        }
    }
    if let Some(conc) = ob.get("congestion_control").and_then(Value::as_str) {
        node.extra.insert("congestion_control".into(), conc.to_string());
    }
    node.label = ob.get("tag").and_then(Value::as_str).map(str::to_string);
    Ok(Some(node))
}

fn apply_tls(node: &mut Node, tls: Option<&Value>) {
    let Some(tls) = tls else { return };
    if tls.get("enabled").and_then(Value::as_bool) == Some(false) {
        node.security = Security::None;
        return;
    }
    node.security = Security::Tls;
    node.sni = tls
        .get("server_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(alpn) = tls.get("alpn").and_then(Value::as_array) {
        node.alpn = alpn
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
    }
    node.allow_insecure = tls.get("insecure").and_then(Value::as_bool).unwrap_or(false);
    if let Some(utls) = tls.get("utls").and_then(Value::as_object) {
        if let Some(fp) = utls.get("fingerprint").and_then(Value::as_str) {
            node.fingerprint = Some(fp.to_string());
        }
    }
    if let Some(reality) = tls.get("reality").and_then(Value::as_object) {
        if reality.get("enabled").and_then(Value::as_bool).unwrap_or(true) {
            node.security = Security::Reality;
            node.public_key = reality
                .get("public_key")
                .and_then(Value::as_str)
                .map(str::to_string);
            node.short_id = reality
                .get("short_id")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
    }
}

fn apply_transport(node: &mut Node, ob: &Value) {
    // `v2ray_transport` (1.11+) wins over the legacy `transport`.
    let t = ob
        .get("v2ray_transport")
        .or_else(|| ob.get("transport"));
    let Some(t) = t else {
        if let Some(net) = ob.get("network").and_then(Value::as_str) {
            node.transport.kind = TransportKind::parse(net);
        }
        return;
    };
    node.transport.kind = t
        .get("type")
        .and_then(Value::as_str)
        .map(TransportKind::parse)
        .unwrap_or_default();
    node.transport.path = t.get("path").and_then(Value::as_str).map(str::to_string);
    node.transport.host = t
        .get("host")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
        })
        .or_else(|| {
            t.get("headers")
                .and_then(|h| h.get("Host"))
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    node.transport.service_name = t
        .get("service_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    node.transport.mode = t.get("method").and_then(Value::as_str).map(str::to_string);
    node.transport.header_type = t
        .get("headers")
        .and_then(|h| h.get("type"))
        .and_then(Value::as_str)
        .map(str::to_string);
}

// ---------------------------------------------------------------- rendering

pub fn render(nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<String> {
    if nodes.is_empty() {
        return Err(Error::MalformedLink("no nodes to render".into()));
    }
    let mut outbounds: Vec<Value> = Vec::new();
    let mut tags: Vec<String> = Vec::new();

    for (i, node) in nodes.iter().enumerate() {
        let tag = node
            .label
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| format!("{}-{}", node.protocol.as_str(), i));
        tags.push(tag.clone());
        let mut ob = outbound_body(node)?;
        if let Value::Object(map) = &mut ob {
            map.insert("tag".into(), json!(tag));
        }
        outbounds.push(ob);
    }

    let mut config = json!({
        "log": { "level": "warn", "timestamp": true },
        "outbounds": outbounds,
    });

    if let Some(spec) = balancer {
        let members = super::xray::balancer_members(nodes, spec);
        let mut group = Map::new();
        group.insert("type".into(), json!(spec.kind.singbox_name()));
        group.insert("tag".into(), json!(spec.name));
        group.insert("outbounds".into(), json!(members));
        if !matches!(spec.kind, BalancerKind::Selector | BalancerKind::Random) {
            group.insert(
                "url".into(),
                json!(spec.url.clone().unwrap_or_else(|| "https://www.gstatic.com/generate_204".into())),
            );
            group.insert(
                "interval".into(),
                json!(format!("{}s", spec.interval.unwrap_or(300))),
            );
            if let Some(tol) = spec.tolerance {
                group.insert("tolerance".into(), json!(tol));
            }
        }
        config["outbounds"]
            .as_array_mut()
            .unwrap()
            .push(Value::Object(group));
    }

    config["outbounds"].as_array_mut().unwrap().push(json!({
        "type": "direct",
        "tag": "direct",
    }));

    Ok(serde_json::to_string_pretty(&config)?)
}

fn outbound_body(node: &Node) -> Result<Value> {
    let mut map = Map::new();
    map.insert("type".into(), json!(singbox_type(node.protocol)?));
    map.insert("server".into(), json!(node.address));
    map.insert("server_port".into(), json!(node.port));

    match node.protocol {
        Protocol::Vless | Protocol::Vmess | Protocol::Trojan | Protocol::Anytls => {
            if let Some(uuid) = &node.uuid {
                map.insert("uuid".into(), json!(uuid));
            }
        }
        Protocol::Hysteria | Protocol::Hysteria2 => {
            if let Some(pw) = &node.password {
                map.insert("password".into(), json!(pw));
            }
        }
        Protocol::Shadowsocks => {
            map.insert("method".into(), json!(node.method.clone().unwrap_or_default()));
            map.insert("password".into(), json!(node.password.clone().unwrap_or_default()));
        }
        Protocol::Socks => {
            map.insert("version".into(), json!("5"));
            if let Some(u) = &node.uuid {
                map.insert("username".into(), json!(u));
            }
            if let Some(p) = &node.password {
                map.insert("password".into(), json!(p));
            }
        }
        Protocol::Tuic => {
            if let Some(u) = &node.uuid {
                map.insert("uuid".into(), json!(u));
            }
            if let Some(p) = &node.password {
                map.insert("password".into(), json!(p));
            }
        }
        Protocol::Http => {
            if let Some(u) = &node.uuid {
                map.insert("username".into(), json!(u));
            }
            if let Some(p) = &node.password {
                map.insert("password".into(), json!(p));
            }
        }
        Protocol::Wireguard => return Err(Error::UnsupportedProtocol("wireguard".into())),
    }

    if let Some(flow) = &node.flow {
        map.insert("flow".into(), json!(flow));
    }
    if let Some(tls) = tls_object(node) {
        map.insert("tls".into(), tls);
    }
    if let Some(t) = transport_object(&node.transport) {
        map.insert("v2ray_transport".into(), t);
    }
    if node.up_mbps.is_some() || node.down_mbps.is_some() {
        let mut updown = Map::new();
        if let Some(v) = node.up_mbps {
            updown.insert("up".into(), json!(v));
        }
        if let Some(v) = node.down_mbps {
            updown.insert("down".into(), json!(v));
        }
        map.insert("up_mbps".into(), json!(node.up_mbps.unwrap_or(0)));
        map.insert("down_mbps".into(), json!(node.down_mbps.unwrap_or(0)));
    }
    if let Some(hop) = &node.port_hopping {
        map.insert(
            "server_ports".into(),
            json!(hop.split(',').filter(|s| !s.is_empty()).collect::<Vec<_>>()),
        );
    }
    if let Some(obfs) = &node.obfs {
        let mut o = Map::new();
        o.insert("type".into(), json!(obfs));
        if let Some(pw) = node.extra.get("obfs-password") {
            o.insert("password".into(), json!(pw));
        }
        map.insert("obfs".into(), Value::Object(o));
    }
    Ok(Value::Object(map))
}

fn singbox_type(protocol: Protocol) -> Result<&'static str> {
    Ok(match protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        Protocol::Trojan => "trojan",
        Protocol::Hysteria => "hysteria",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Socks => "socks",
        Protocol::Http => "http",
        Protocol::Tuic => "tuic",
        Protocol::Anytls => "anytls",
        Protocol::Wireguard => return Err(Error::UnsupportedProtocol("wireguard".into())),
    })
}

fn tls_object(node: &Node) -> Option<Value> {
    if node.security == Security::None {
        return None;
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));
    if let Some(sni) = node.effective_sni() {
        tls.insert("server_name".into(), json!(sni));
    }
    if !node.alpn.is_empty() {
        tls.insert("alpn".into(), json!(node.alpn));
    }
    if node.allow_insecure {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(fp) = &node.fingerprint {
        tls.insert(
            "utls".into(),
            json!({ "enabled": true, "fingerprint": fp }),
        );
    }
    if node.security == Security::Reality {
        let mut reality = Map::new();
        reality.insert("enabled".into(), json!(true));
        if let Some(pb) = &node.public_key {
            reality.insert("public_key".into(), json!(pb));
        }
        if let Some(sid) = &node.short_id {
            reality.insert("short_id".into(), json!(sid));
        }
        tls.insert("reality".into(), Value::Object(reality));
    }
    Some(Value::Object(tls))
}

fn transport_object(t: &Transport) -> Option<Value> {
    if t.kind == TransportKind::Tcp {
        return None;
    }
    let mut map = Map::new();
    map.insert("type".into(), json!(t.kind.as_str()));
    if let Some(path) = &t.path {
        map.insert("path".into(), json!(path));
    }
    match t.kind {
        TransportKind::Ws | TransportKind::Httpupgrade | TransportKind::Xhttp => {
            if let Some(host) = &t.host {
                map.insert("headers".into(), json!({ "Host": host }));
                if t.kind == TransportKind::Xhttp {
                    map.insert("host".into(), json!(split_list(host)));
                }
            }
            if let Some(mode) = &t.mode {
                if t.kind == TransportKind::Xhttp {
                    map.insert("mode".into(), json!(mode));
                }
            }
        }
        TransportKind::Grpc => {
            map.insert(
                "service_name".into(),
                json!(t.service_name.clone().unwrap_or_default()),
            );
        }
        TransportKind::Quic => {
            map.insert(
                "security".into(),
                json!(t.header_type.clone().unwrap_or_else(|| "none".into())),
            );
            if let Some(key) = &t.seed {
                map.insert("key".into(), json!(key));
            }
        }
        _ => {}
    }
    Some(Value::Object(map))
}

/// Flatten every outbound (including those inside groups) into plain links.
pub fn decompose(bundle: &Bundle) -> Result<String> {
    crate::links::render_all(&bundle.nodes)
}
