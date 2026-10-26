//! trojan:// password@host:port?params#name

use crate::error::{Error, Result};
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol, Security};
use crate::util::{
    build_query_with_transport, collect_extra, parse_bool, percent_encode, split_list,
    transport_from_query,
};

pub fn parse_str(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    parse(&raw)
}

pub fn parse(raw: &RawLink) -> Result<Node> {
    let password = raw
        .userinfo
        .clone()
        .filter(|p| !p.is_empty())
        .ok_or(Error::MissingField("password"))?;
    let port = raw.port_or(443)?;
    let mut node = Node::new(Protocol::Trojan, raw.host.clone(), port);
    node.password = Some(password);
    node.transport = transport_from_query(raw);
    node.security = Security::Tls;
    if let Some(sec) = raw.q_ci("security") {
        node.security = Security::parse(&sec);
    }
    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("fp") {
        node.fingerprint = Some(v);
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw
        .q_ci("allowInsecure")
        .or_else(|| raw.q_ci("insecure"))
        .or_else(|| raw.q_ci("skip-cert-verify"))
    {
        node.allow_insecure = parse_bool(&v);
    }
    if node.label.is_none() {
        node.label = raw.label();
    }
    node.extra.extend(collect_extra(raw));
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let password = node.password.as_deref().ok_or(Error::MissingField("password"))?;
    let mut items: Vec<(String, String)> = Vec::new();
    if node.security != Security::None {
        items.push(("security".into(), node.security.as_str().into()));
    }
    if let Some(v) = &node.sni {
        items.push(("sni".into(), v.clone()));
    }
    if let Some(v) = &node.fingerprint {
        items.push(("fp".into(), v.clone()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if node.allow_insecure {
        items.push(("allowInsecure".into(), "1".into()));
    }
    for (k, v) in &node.extra {
        items.push((k.clone(), v.clone()));
    }
    let query = build_query_with_transport(&items, &node.transport);
    Ok(format!(
        "trojan://{}@{}:{}{}{}",
        password,
        host_part(&node.address),
        node.port,
        query,
        node.label
            .as_deref()
            .map(|l| format!("#{}", percent_encode(l)))
            .unwrap_or_default(),
    ))
}
