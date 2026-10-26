//! vmess:// links.
//!
//! Two flavours exist in the wild:
//! * **VMessAEAD** — `vmess://<base64 of a JSON object>` (the modern format),
//! * **legacy ("std")** — the same JSON but with a UUID scrambled by the
//!   `alterId`-derived transformation, and TLS in the `net`/`type` field.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::node::{Node, Protocol, Security, Transport, TransportKind};
use crate::util::{b64_string, parse_bool, split_list};

/// The JSON payload carried inside `vmess://`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VmessJson {
    /// protocol version, always 2
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
    /// user id
    #[serde(rename = "ps", skip_serializing_if = "Option::is_none")]
    pub ps: Option<String>,
    /// port
    #[serde(rename = "add", skip_serializing_if = "Option::is_none")]
    pub add: Option<String>,
    /// server port
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// aid / alterId
    #[serde(rename = "aid", skip_serializing_if = "Option::is_none")]
    pub aid: Option<String>,
    /// scy security
    #[serde(rename = "scy", skip_serializing_if = "Option::is_none")]
    pub scy: Option<String>,
    /// net: tcp/ws/h2/grpc/quic/kcp
    #[serde(rename = "net", skip_serializing_if = "Option::is_none")]
    pub net: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub net_type: Option<String>,
    #[serde(rename = "host", skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(rename = "path", skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "tls", skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
    #[serde(rename = "sni", skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(rename = "alpn", skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(rename = "fp", skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    /// service name for gRPC
    #[serde(rename = "serviceName", skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(rename = "mode", skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remarks: Option<String>,
    /// REALITY public key, seen in some generators
    #[serde(rename = "pbk", skip_serializing_if = "Option::is_none")]
    pub pbk: Option<String>,
    #[serde(rename = "sid", skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(rename = "spx", skip_serializing_if = "Option::is_none")]
    pub spx: Option<String>,
    #[serde(rename = "allowInsecure", skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<String>,
}

/// Decode the base64 payload; some generators percent-encode it first.
pub fn decode_payload(payload: &str) -> Result<Vec<u8>> {
    let payload = crate::util::percent_decode(payload.trim());
    crate::util::b64_decode(&payload)
}

pub fn parse_str(link: &str) -> Result<Node> {
    let payload = link
        .trim()
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or_default()
        .trim()
        .trim_end_matches('\r')
        .trim_end_matches('\n');
    if payload.is_empty() {
        return Err(Error::MalformedLink("empty vmess payload".into()));
    }
    let decoded = decode_payload(payload)?;
    let json: VmessJson = serde_json::from_slice(&decoded)
        .map_err(|e| Error::MalformedLink(format!("vmess json: {e}")))?;

    let address = json
        .add
        .clone()
        .ok_or(Error::MissingField("add"))?;
    let port: u16 = json
        .port
        .as_deref()
        .ok_or(Error::MissingField("port"))?
        .parse()
        .map_err(|_| crate::error::field_err("port", json.port.clone().unwrap_or_default()))?;
    let id = json.id.clone().ok_or(Error::MissingField("id"))?;
    let aid: u32 = json.aid.as_deref().unwrap_or("0").parse().unwrap_or(0);
    if aid != 0 {
        // Legacy alterId != 0 scrambles the uuid with an md5 chain and was
        // removed from every current client; refuse rather than guess.
        return Err(Error::UnsupportedProtocol(format!(
            "vmess with alterId {aid} is not supported (legacy MD5 handshake)"
        )));
    }
    let uuid = normalize_uuid(&id)?;

    let net = json.net.clone().unwrap_or_else(|| "tcp".into());
    let mut transport = Transport {
        kind: TransportKind::parse(&net),
        path: json.path.clone().filter(|p| !p.is_empty()),
        host: json.host.clone().filter(|h| !h.is_empty()),
        service_name: json
            .service_name
            .clone()
            .filter(|s| !s.is_empty()),
        mode: json.mode.clone().filter(|m| !m.is_empty()),
        header_type: json.net_type.clone().filter(|t| !t.is_empty()),
        ..Transport::default()
    };
    // `type: none` means "no obfuscation" and carries no information, except
    // for tcp http obfs where it names the masquerade.
    if transport.header_type.as_deref() == Some("none")
        && transport.kind != TransportKind::Tcp
    {
        transport.header_type = None;
    }

    let tls = json.tls.as_deref().unwrap_or("");
    let security = if tls.eq_ignore_ascii_case("tls") {
        Security::Tls
    } else if tls.eq_ignore_ascii_case("reality") {
        Security::Reality
    } else if tls.eq_ignore_ascii_case("xtls") {
        Security::Tls
    } else {
        Security::None
    };

    let mut node = Node::new(Protocol::Vmess, address, port).with_uuid(uuid);
    node.security = security;
    node.transport = transport;
    node.sni = json
        .sni
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            json.host
                .clone()
                .filter(|h| !h.is_empty() && !net.eq_ignore_ascii_case("tcp"))
        });
    if let Some(v) = json.alpn.as_deref().filter(|a| !a.is_empty()) {
        node.alpn = split_list(v);
    }
    node.fingerprint = json.fp.clone().filter(|f| !f.is_empty());
    node.public_key = json.pbk.clone().filter(|s| !s.is_empty());
    node.short_id = json.sid.clone().filter(|s| !s.is_empty());
    node.spider_x = json.spx.clone().filter(|s| !s.is_empty());
    node.allow_insecure = json
        .allow_insecure
        .as_deref()
        .map(parse_bool)
        .unwrap_or(false);
    node.label = json.remarks.clone().filter(|r| !r.is_empty());
    if let Some(scy) = json.scy.filter(|s| !s.is_empty() && s != "auto") {
        node.extra.insert("scy".into(), scy);
    }
    Ok(node)
}

pub fn render(node: &Node) -> Result<String> {
    let uuid = node.uuid.as_deref().ok_or(Error::MissingField("uuid"))?;
    let json = VmessJson {
        v: Some("2".into()),
        ps: node.label.clone(),
        add: Some(node.address.clone()),
        port: Some(node.port.to_string()),
        id: Some(uuid.to_string()),
        aid: Some("0".into()),
        scy: Some(node.extra.get("scy").cloned().unwrap_or_else(|| "auto".into())),
        net: Some(node.transport.kind.as_str().to_string()),
        net_type: match (&node.transport.kind, &node.transport.header_type) {
            (TransportKind::Tcp, header) => Some(header.clone().unwrap_or_else(|| "none".into())),
            (_, header) => header.clone(),
        },
        host: node.transport.host.clone(),
        path: node.transport.path.clone(),
        tls: Some(match node.security {
            Security::None => String::new(),
            Security::Tls => "tls".into(),
            Security::Reality => "reality".into(),
        }),
        sni: node.sni.clone(),
        alpn: if node.alpn.is_empty() {
            None
        } else {
            Some(node.alpn.join(","))
        },
        fp: node.fingerprint.clone(),
        service_name: node.transport.service_name.clone(),
        mode: node.transport.mode.clone(),
        remarks: node.label.clone(),
        pbk: node.public_key.clone(),
        sid: node.short_id.clone(),
        spx: node.spider_x.clone(),
        allow_insecure: node.allow_insecure.then(|| "1".to_string()),
    };
    let mut json = json;
    json.ps = None; // keep payload minimal; remark carries the name
    let payload = b64_string(&serde_json::to_vec(&json)?);
    Ok(format!("vmess://{}", payload))
}

/// AEAD links carry the uuid either hyphenated or as 32 hex chars.
fn normalize_uuid(id: &str) -> Result<String> {
    let trimmed = id.trim().trim_start_matches("0x");
    uuid::Uuid::parse_str(trimmed)
        .map(|u| u.hyphenated().to_string())
        .map_err(|_| Error::MalformedLink(format!("bad vmess uuid: {id}")))
}
