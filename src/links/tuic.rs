//! `tuic://` links (TUIC v5).

use crate::error::{Error, Result};
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol, Security};
use crate::util::{build_query, parse_bool, percent_encode, split_list};

pub fn parse(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    let port = raw.port_or(443)?;
    let (uuid, password) = match raw.userinfo.clone() {
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
            None => (Some(ui), None),
        },
        None => (None, None),
    };
    let mut node = Node::new(Protocol::Tuic, raw.host.clone(), port);
    node.uuid = uuid;
    node.password = password;
    node.security = Security::Tls;
    if let Some(v) = raw.q_ci("congestion_control").or_else(|| raw.q_ci("congestion")) {
        node.obfs = Some(v);
    }
    if let Some(v) = raw.q_ci("udp_relay_mode") {
        node.extra.insert("udp_relay_mode".into(), v);
    }
    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw.q_ci("allow_insecure").or_else(|| raw.q_ci("insecure")) {
        node.allow_insecure = parse_bool(&v);
    }
    node.label = raw.label();
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let uuid = node.uuid.as_deref().ok_or(Error::MissingField("uuid"))?;
    let mut items: Vec<(String, String)> = Vec::new();
    if let Some(v) = &node.sni {
        items.push(("sni".into(), v.clone()));
    }
    if let Some(v) = &node.obfs {
        items.push(("congestion_control".into(), v.clone()));
    }
    for (k, v) in &node.extra {
        items.push((k.clone(), v.clone()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if node.allow_insecure {
        items.push(("allow_insecure".into(), "1".into()));
    }
    let creds = match node.password.as_deref() {
        Some(p) if !p.is_empty() => format!("{}:{}", uuid, percent_encode(p)),
        _ => uuid.to_string(),
    };
    Ok(format!(
        "tuic://{}@{}:{}{}{}",
        creds,
        host_part(&node.address),
        node.port,
        build_query(&items),
        node.label
            .as_deref()
            .map(|l| format!("#{}", percent_encode(l)))
            .unwrap_or_default(),
    ))
}
