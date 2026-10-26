//! vless:// UUID@host:port?params#name
//!
//! Reference: XRay docs "Sharing Link Format".

use crate::error::{Error, Result};
use crate::links::RawLink;
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
    let uuid = raw
        .userinfo
        .clone()
        .filter(|u| !u.is_empty())
        .ok_or(Error::MissingField("uuid"))?;
    let port = raw.port_or(443)?;
    let mut node = Node::new(Protocol::Vless, raw.host.clone(), port).with_uuid(uuid);

    node.transport = transport_from_query(raw);
    if let Some(sec) = raw.q_ci("security") {
        node.security = Security::parse(&sec);
    }
    if let Some(enc) = raw.q_ci("encryption") {
        if !enc.is_empty() && !enc.eq_ignore_ascii_case("none") {
            node.extra.insert("encryption".into(), enc);
        }
    }
    if let Some(v) = raw.q_ci("flow") {
        node.flow = Some(v);
    }
    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
    }
    if let Some(v) = raw.q_ci("fp") {
        node.fingerprint = Some(v);
    }
    if let Some(v) = raw.q_ci("pbk") {
        node.public_key = Some(v);
    }
    if let Some(v) = raw.q_ci("sid") {
        node.short_id = Some(v);
    }
    if let Some(v) = raw.q_ci("spx") {
        node.spider_x = Some(v);
    }
    if let Some(v) = raw.q_ci("alpn") {
        node.alpn = split_list(&v);
    }
    if let Some(v) = raw
        .q_ci("allowInsecure")
        .or_else(|| raw.q_ci("insecure"))
        .or_else(|| raw.q_ci("allow_insecure"))
        .or_else(|| raw.q_ci("skip-cert-verify"))
    {
        node.allow_insecure = parse_bool(&v);
    }
    if let Some(v) = raw.q_ci("label").or_else(|| raw.label()) {
        node.label = Some(v);
    }
    node.extra.extend(collect_extra(raw));
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let uuid = node.uuid.as_deref().ok_or(Error::MissingField("uuid"))?;
    let mut items: Vec<(String, String)> = Vec::new();
    if node.security != Security::None {
        items.push(("security".into(), node.security.as_str().into()));
    }
    // Every vless share link carries `encryption`; clients that see it missing
    // fall back to `none` anyway, but emitting it matches what v2rayN, Happ and
    // XRay's own docs produce.
    items.push((
        "encryption".into(),
        node.extra
            .get("encryption")
            .cloned()
            .unwrap_or_else(|| "none".into()),
    ));
    if let Some(v) = node.flow.as_deref().filter(|f| !f.is_empty()) {
        items.push(("flow".into(), v.into()));
    }
    if let Some(sni) = node.sni.as_deref().filter(|s| !s.is_empty()) {
        items.push(("sni".into(), sni.into()));
    }
    if let Some(v) = node.fingerprint.as_deref().filter(|f| !f.is_empty()) {
        items.push(("fp".into(), v.into()));
    }
    if let Some(v) = node.public_key.as_deref().filter(|p| !p.is_empty()) {
        items.push(("pbk".into(), v.into()));
    }
    // An empty `sid=`/`spx=` is not the same as an absent one for some clients.
    if let Some(v) = node.short_id.as_deref().filter(|s| !s.is_empty()) {
        items.push(("sid".into(), v.into()));
    }
    if let Some(v) = node.spider_x.as_deref().filter(|s| !s.is_empty()) {
        items.push(("spx".into(), v.into()));
    }
    if !node.alpn.is_empty() {
        items.push(("alpn".into(), node.alpn.join(",")));
    }
    if node.allow_insecure {
        items.push(("allowInsecure".into(), "1".into()));
    }
    for (k, v) in &node.extra {
        if k != "encryption"
            && !v.is_empty()
            && !crate::util::INTERNAL_MARKERS.iter().any(|m| m == k)
        {
            items.push((k.clone(), v.clone()));
        }
    }

    Ok(format!(
        "vless://{}@{}:{}{}{}",
        uuid,
        host_part(&node.address),
        node.port,
        build_query_with_transport(&items, &node.transport),
        node.label
            .as_deref()
            .map(|l| format!("#{}", percent_encode(l)))
            .unwrap_or_default(),
    ))
}

pub(crate) fn host_part(address: &str) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{}]", address)
    } else {
        address.to_string()
    }
}
