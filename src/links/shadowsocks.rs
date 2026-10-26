//! `ss://` legacy and SIP002 links.

use crate::error::{Error, Result};
use crate::links::{vless::host_part, RawLink};
use crate::node::{Node, Protocol};
use crate::util::{b64_decode, percent_encode};

pub fn parse(link: &str) -> Result<Node> {
    let raw = RawLink::parse(link)?;
    // SIP002: ss://base64(method:pass)@host:port#name
    // legacy:  ss://base64(method:pass@host:port)#name
    if let (Some(userinfo), Some(port)) = (raw.userinfo.clone(), raw.port) {
        if let Some((method, password)) = split_creds(&userinfo) {
            let mut node = Node::new(Protocol::Shadowsocks, raw.host.clone(), port);
            node.method = Some(method);
            node.password = Some(password);
            node.label = raw.label();
            return Ok(node);
        }
    }

    let payload = raw
        .userinfo
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| format!("{}@{}", raw.host, raw.port.map(|p| p.to_string()).unwrap_or_default()));
    let decoded = String::from_utf8(b64_decode(&payload)?)
        .map_err(|_| Error::Base64("ss payload is not utf8".into()))?;
    let (creds, hostport) = decoded
        .rsplit_once('@')
        .ok_or(Error::MalformedLink("ss payload has no host".into()))?;
    let (method, password) = creds
        .split_once(':')
        .ok_or(Error::MalformedLink("ss creds have no colon".into()))?;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| crate::error::field_err("port", p))?;
            (h.trim_matches(|c| c == '[' || c == ']').to_string(), port)
        }
        None => return Err(Error::MissingField("port")),
    };
    let mut node = Node::new(Protocol::Shadowsocks, host, port);
    node.method = Some(method.to_string());
    node.password = Some(password.to_string());
    node.label = raw.label();
    Ok(node)
}

fn split_creds(userinfo: &str) -> Option<(String, String)> {
    let decoded = match String::from_utf8(b64_decode(userinfo).ok()?) {
        Ok(d) => d,
        Err(_) => return None,
    };
    decoded
        .split_once(':')
        .map(|(m, p)| (m.to_string(), p.to_string()))
        .filter(|(m, _)| !m.is_empty())
}

pub fn render(node: &Node) -> Result<String> {
    let method = node.method.as_deref().ok_or(Error::MissingField("method"))?;
    let creds = format!("{method}:{}", node.password.as_deref().unwrap_or_default());
    let creds_b64 = crate::util::b64_string(creds.as_bytes());
    let mut link = format!(
        "ss://{}@{}:{}",
        creds_b64.trim_end_matches('='),
        host_part(&node.address),
        node.port
    );
    if let Some(sni) = &node.sni {
        link.push_str(&format!("?sni={}", percent_encode(sni)));
    }
    if node.allow_insecure {
        link.push_str("&skip-cert-verify=1");
    }
    if let Some(label) = &node.label {
        link.push('#');
        link.push_str(&percent_encode(label));
    }
    Ok(link)
}
