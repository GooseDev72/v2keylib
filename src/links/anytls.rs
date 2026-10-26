//! `anytls://` links.

use crate::error::{Error, Result};
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol, Security, TransportKind};
use crate::util::{parse_bool, percent_encode, split_list};

pub fn parse(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    let port = raw.port_or(443)?;
    let mut node = Node::new(Protocol::Anytls, raw.host.clone(), port);
    node.security = Security::Tls;
    node.uuid = raw
        .q_ci("uuid")
        .or_else(|| raw.userinfo.clone())
        .filter(|u| !u.is_empty());
    node.password = raw.q_ci("password");
    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw.q_ci("fp") {
        node.fingerprint = Some(v);
    }
    if let Some(v) = raw
        .q_ci("insecure")
        .or_else(|| raw.q_ci("allowInsecure"))
    {
        node.allow_insecure = parse_bool(&v);
    }
    if let Some(v) = raw.q_ci("type") {
        node.transport.kind = TransportKind::parse(&v);
    }
    node.label = raw.label();
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let uuid = node.uuid.as_deref().ok_or(Error::MissingField("uuid"))?;
    let mut items: Vec<(String, String)> = vec![("uuid".into(), uuid.to_string())];
    if let Some(v) = &node.password {
        items.push(("password".into(), v.clone()));
    }
    if let Some(v) = &node.sni {
        items.push(("sni".into(), v.clone()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if let Some(v) = &node.fingerprint {
        items.push(("fp".into(), v.clone()));
    }
    if node.allow_insecure {
        items.push(("insecure".into(), "1".into()));
    }
    if node.transport.kind != TransportKind::Tcp {
        items.push(("type".into(), node.transport.kind.as_str().into()));
    }
    Ok(format!(
        "anytls://{}@{}:{}{}{}",
        uuid,
        host_part(&node.address),
        node.port,
        crate::util::build_query(&items),
        node.label
            .as_deref()
            .map(|l| format!("#{}", percent_encode(l)))
            .unwrap_or_default(),
    ))
}
