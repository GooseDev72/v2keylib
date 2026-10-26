//! `socks://` / `socks5://` links (HTTP-style userinfo, optional TLS).

use crate::error::Result;
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol, Security};
use crate::util::{parse_bool, percent_encode};

pub fn parse(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    let port = raw.port_or(1080)?;
    let mut node = Node::new(Protocol::Socks, raw.host.clone(), port);
    if let Some(ui) = raw.userinfo.clone() {
        let (u, p) = ui.split_once(':').unwrap_or((ui.as_str(), ""));
        node.uuid = Some(u.to_string());
        node.password = Some(p.to_string());
    }
    if let Some(v) = raw.q_ci("sni").or_else(|| raw.q_ci("peer")) {
        node.sni = Some(v);
        node.security = Security::Tls;
    }
    if let Some(v) = raw.q_ci("tls").or_else(|| raw.q_ci("security")) {
        node.security = Security::parse(&v);
    }
    if let Some(v) = raw.q_ci("insecure").or_else(|| raw.q_ci("allowInsecure")) {
        node.allow_insecure = parse_bool(&v);
    }
    node.label = raw.label();
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let mut items: Vec<(String, String)> = Vec::new();
    if let Some(v) = &node.sni {
        items.push(("sni".into(), v.clone()));
    }
    if node.security != Security::None {
        items.push(("security".into(), node.security.as_str().into()));
    }
    if node.allow_insecure {
        items.push(("insecure".into(), "1".into()));
    }
    let creds = match (&node.uuid, &node.password) {
        (Some(u), p) => format!(
            "{}:{}@",
            percent_encode(u),
            percent_encode(p.as_deref().unwrap_or_default())
        ),
        _ => String::new(),
    };
    let query = crate::util::build_query(&items);
    Ok(format!(
        "socks://{}{}:{}{}{}",
        creds,
        host_part(&node.address),
        node.port,
        if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query.trim_start_matches('?'))
        },
        node.label
            .as_deref()
            .map(|l| format!("#{}", percent_encode(l)))
            .unwrap_or_default(),
    ))
}
