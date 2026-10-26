//! `hysteria2://` / `hy2://` (v2) and `hysteria://` / `hy://` (v1) links.

use crate::error::Result;
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol, Security};
use crate::util::{
    build_query, collect_extra, parse_bool, percent_encode, split_list,
};

/// `hysteria2://[auth@]host:port[/][?sni=..&obfs=..&mport=..]`
pub fn parse_v2_str(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    parse_v2(&raw)
}

pub fn parse_v1_str(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    parse_v1(&raw)
}

pub fn parse_v2(raw: &RawLink) -> Result<Node> {
    let port = raw.port_or(443)?;
    let mut node = Node::new(Protocol::Hysteria2, raw.host.clone(), port);
    node.security = Security::Tls;
    node.password = raw.userinfo.clone().filter(|p| !p.is_empty());

    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("insecure").or_else(|| raw.q_ci("allowInsecure")) {
        node.allow_insecure = parse_bool(&v);
    }
    if let Some(v) = raw.q_ci("obfs") {
        node.obfs = Some(v);
    }
    if let Some(v) = raw.q_ci("obfs-password").or_else(|| raw.q_ci("obfsParam")) {
        node.extra.insert("obfs-password".into(), v);
    }
    if let Some(v) = raw
        .q_ci("mport")
        .or_else(|| raw.q_ci("port-hopping"))
        .or_else(|| raw.q_ci("ports"))
    {
        node.port_hopping = Some(v);
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw.q_ci("upmbps").or_else(|| raw.q_ci("up")) {
        node.up_mbps = v.parse().ok();
    }
    if let Some(v) = raw.q_ci("downmbps").or_else(|| raw.q_ci("down")) {
        node.down_mbps = v.parse().ok();
    }
    if let Some(v) = raw.q_ci("pinSHA256") {
        node.extra.insert("pinSHA256".into(), v);
    }
    if node.label.is_none() {
        node.label = raw.label();
    }
    node.extra.extend(collect_extra(raw));
    Ok(node)
}

pub fn render_v2(node: &Node) -> Result<String> {
    let mut items: Vec<(String, String)> = Vec::new();
    if let Some(v) = &node.sni {
        items.push(("sni".into(), v.clone()));
    }
    if let Some(v) = &node.obfs {
        items.push(("obfs".into(), v.clone()));
    }
    if let Some(v) = node.extra.get("obfs-password") {
        items.push(("obfs-password".into(), v.clone()));
    }
    if let Some(v) = &node.port_hopping {
        items.push(("mport".into(), v.clone()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if let Some(v) = node.up_mbps {
        items.push(("upmbps".into(), v.to_string()));
    }
    if let Some(v) = node.down_mbps {
        items.push(("downmbps".into(), v.to_string()));
    }
    if node.allow_insecure {
        items.push(("insecure".into(), "1".into()));
    }
    for (k, v) in &node.extra {
        if k != "obfs-password" {
            items.push((k.clone(), v.clone()));
        }
    }

    let auth = node.password.as_deref().unwrap_or_default();
    let label = node
        .label
        .as_deref()
        .map(|l| format!("#{}", percent_encode(l)))
        .unwrap_or_default();
    let query = build_query(&items);
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query.trim_start_matches('?'))
    };
    Ok(format!(
        "hysteria2://{}@{}:{}{}{}",
        percent_encode(auth),
        host_part(&node.address),
        node.port,
        query,
        label
    ))
}

/// `hysteria://host:port?auth=..&protocol=udp&peer=..&upmbps=..`
pub fn parse_v1(raw: &RawLink) -> Result<Node> {
    let port = raw.port_or(443)?;
    let mut node = Node::new(Protocol::Hysteria, raw.host.clone(), port);
    node.security = Security::Tls;
    node.password = raw
        .q_ci("auth")
        .or_else(|| raw.q_ci("auth_str"))
        .or_else(|| raw.userinfo.clone())
        .filter(|p| !p.is_empty());

    if let Some(v) = raw.q_ci("peer").or_else(|| raw.q_ci("sni")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("insecure").or_else(|| raw.q_ci("allowInsecure")) {
        node.allow_insecure = parse_bool(&v);
    }
    if let Some(v) = raw.q_ci("obfs") {
        node.obfs = Some(v);
    }
    if let Some(v) = raw.q_ci("upmbps").or_else(|| raw.q_ci("up")) {
        node.up_mbps = v.parse().ok();
    }
    if let Some(v) = raw.q_ci("downmbps").or_else(|| raw.q_ci("down")) {
        node.down_mbps = v.parse().ok();
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw.q_ci("protocol") {
        node.extra.insert("protocol".into(), v);
    }
    if node.label.is_none() {
        node.label = raw.label();
    }
    node.extra.extend(collect_extra(raw));
    Ok(node)
}

pub fn render_v1(node: &Node) -> Result<String> {
    let mut items: Vec<(String, String)> = Vec::new();
    if let Some(v) = &node.password {
        items.push(("auth".into(), v.clone()));
    }
    if let Some(v) = &node.sni {
        items.push(("peer".into(), v.clone()));
    }
    if let Some(v) = &node.obfs {
        items.push(("obfs".into(), v.clone()));
    }
    if let Some(v) = node.up_mbps {
        items.push(("upmbps".into(), v.to_string()));
    }
    if let Some(v) = node.down_mbps {
        items.push(("downmbps".into(), v.to_string()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if node.allow_insecure {
        items.push(("insecure".into(), "1".into()));
    }
    for (k, v) in &node.extra {
        items.push((k.clone(), v.clone()));
    }
    let label = node
        .label
        .as_deref()
        .map(|l| format!("#{}", percent_encode(l)))
        .unwrap_or_default();
    Ok(format!(
        "hysteria://{}:{}{}{}",
        host_part(&node.address),
        node.port,
        build_query(&items),
        label
    ))
}
