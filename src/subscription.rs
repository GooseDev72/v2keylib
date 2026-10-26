//! Subscription fetching, stub cleaning and re-publishing.
//!
//! Providers such as HAPPiVPN expect an `X-Hwid` header with a stable 16
//! character device id; it must not change between requests or the provider
//! hands out a different key set each time.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::config::{self, Bundle, Format};
use crate::error::{Error, Result};
use crate::filter::stubs::{self, StubFilter};
use crate::links;
use crate::node::Node;
use crate::util::b64_decode;
use rand::Rng;

/// Happ-style device id: exactly 16 characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XHwid(String);

impl XHwid {
    pub const LEN: usize = 16;
    pub const HEADER: &'static str = "X-Hwid";

    /// The id to send when the caller has none of its own. A provider that
    /// keys on the header wants sixteen characters, and it is better to send a
    /// placeholder than an empty one: empty reads as "client did not say", and
    /// some providers answer that with their worst set.
    pub const ZERO: &'static str = "0000000000000000";

    pub fn zeros() -> Self {
        Self(Self::ZERO.to_string())
    }

    /// Generate a random id. Call once and reuse it for every request.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let id: String = (0..Self::LEN)
            .map(|_| {
                let n: u8 = rng.random_range(0..36);
                if n < 10 {
                    (b'0' + n) as char
                } else {
                    (b'a' + n - 10) as char
                }
            })
            .collect();
        Self(id)
    }

    pub fn parse(raw: impl AsRef<str>) -> Result<Self> {
        let raw = raw.as_ref().trim();
        if raw.chars().count() != Self::LEN {
            return Err(Error::Fetch(format!(
                "{} must be exactly {} characters, got {}",
                Self::HEADER,
                Self::LEN,
                raw.chars().count()
            )));
        }
        if !raw.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::Fetch(format!(
                "{} must be alphanumeric, got {:?}",
                Self::HEADER, raw
            )));
        }
        Ok(Self(raw.to_string()))
    }

    /// The id to send for a whole session, given what the caller asked for.
    ///
    /// Three cases, and they are genuinely different: [`HWID_NONE`] drops the
    /// header for providers that dislike an id they did not issue, an explicit
    /// id is the caller's own device, and "not given" means [`XHwid::ZERO`] —
    /// a placeholder that satisfies a provider expecting sixteen characters.
    pub fn resolve(given: Option<&str>) -> Result<Option<Self>> {
        match given.map(str::trim) {
            None => Ok(Some(Self::zeros())),
            Some(raw) if raw.eq_ignore_ascii_case(HWID_NONE) => Ok(None),
            Some(raw) => Ok(Some(Self::parse(raw)?)),
        }
    }

    /// Reuse the id from the environment if it is there and valid, otherwise
    /// generate one. For a caller who owns a real device id: this is the id
    /// their own client sends, and reusing it is what makes the provider keep
    /// handing out the same key set.
    pub fn from_env_or_generate() -> Self {
        std::env::var("V2KEYLIB_XHWID")
            .ok()
            .and_then(|v| XHwid::parse(v).ok())
            .unwrap_or_else(XHwid::generate)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// The value that means "send no `X-Hwid` at all", wherever an id is taken as
/// text: the flag, the python argument, the configuration file.
pub const HWID_NONE: &str = "none";

impl std::fmt::Display for XHwid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a subscription URL actually contained.
#[derive(Clone, Debug)]
pub enum Subscription {
    Links(Vec<Node>),
    /// Plain links behind a `#name: value` header block.
    ///
    /// Kept apart from [`Subscription::Links`] because the block carries the
    /// profile's name, expiry and support URL, and a caller that re-publishes
    /// the subscription wants to carry them along rather than drop them.
    Generic(Vec<Node>, Headers),
    Config(Bundle),
    Empty,
}

impl Subscription {
    pub fn nodes(self) -> Vec<Node> {
        match self {
            Subscription::Links(nodes) | Subscription::Generic(nodes, _) => nodes,
            Subscription::Config(bundle) => bundle.nodes,
            Subscription::Empty => Vec::new(),
        }
    }

    pub fn bundle(self) -> Bundle {
        match self {
            Subscription::Config(bundle) => bundle,
            Subscription::Links(nodes) | Subscription::Generic(nodes, _) => Bundle {
                nodes,
                groups: Vec::new(),
            },
            Subscription::Empty => Bundle::default(),
        }
    }

    /// The header block, when the body carried one.
    pub fn headers(&self) -> Option<&Headers> {
        match self {
            Subscription::Generic(_, headers) => Some(headers),
            _ => None,
        }
    }
}

/// Parse a subscription body without any network access.
pub fn parse_body(body: &str) -> Result<Subscription> {
    let body = body.trim();
    if body.is_empty() {
        return Ok(Subscription::Empty);
    }

    // 1. plain links, optionally behind a header block
    //
    // The header block is checked first because its presence is what makes a
    // body "generic" rather than a bare link list, and `parse_list` silently
    // ignores the `#` lines, so the two shapes would otherwise be
    // indistinguishable here.
    if body.contains("://") && !body.trim_start().starts_with('{') && !body.contains("\n  ") {
        let generic = parse_generic(body);
        if let Ok(nodes) = links::parse_list(body) {
            if !nodes.is_empty() {
                return Ok(if generic.had_headers {
                    Subscription::Generic(nodes, generic.headers)
                } else {
                    Subscription::Links(nodes)
                });
            }
        }
    }

    // 2. JSON / YAML config (including a JSON array of configs)
    if let Ok(bundle) = config::parse(body) {
        if !bundle.nodes.is_empty() {
            return Ok(Subscription::Config(bundle));
        }
    }

    // 3. base64-wrapped link list
    if let Ok(decoded) = b64_decode(body) {
        if let Ok(text) = String::from_utf8(decoded) {
            if text.contains("://") {
                let nodes = links::parse_list(&text)?;
                if !nodes.is_empty() {
                    return Ok(Subscription::Links(nodes));
                }
            }
        }
    }

    // 4. plain link list, multiline
    let nodes = links::parse_list(body)?;
    if nodes.is_empty() {
        Ok(Subscription::Empty)
    } else {
        Ok(Subscription::Links(nodes))
    }
}

#[derive(Clone, Debug)]
pub struct FetchOptions {
    pub timeout: Duration,
    pub user_agent: String,
    pub accept_invalid_certs: bool,
    /// Sent as `X-Hwid`; some providers key their output on it. `None` sends
    /// no header at all. Defaults to [`XHwid::zeros`]: a caller parsing
    /// someone else's subscription has no device to be, and the provider still
    /// wants sixteen characters.
    pub xhwid: Option<XHwid>,
    /// Any other headers to send.
    pub headers: BTreeMap<String, String>,
    /// Drop placeholder entries (0.0.0.0, 1.1.1.1, 127.0.0.1, ...).
    pub clean_stubs: bool,
    pub stub_filter: StubFilter,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            user_agent: "v2rayNG/1.9.0".into(),
            accept_invalid_certs: false,
            xhwid: Some(XHwid::zeros()),
            headers: BTreeMap::new(),
            clean_stubs: true,
            stub_filter: StubFilter::default(),
        }
    }
}

impl FetchOptions {
    /// Claim to be a different client. Providers often serve a different body
    /// to a client they recognise, so this is a content knob, not a politeness
    /// one.
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        self
    }

    pub fn with_xhwid(mut self, hwid: XHwid) -> Self {
        self.xhwid = Some(hwid);
        self
    }

    /// Send no `X-Hwid` at all. For providers that answer an id they did not
    /// issue worse than they answer none.
    pub fn without_xhwid(mut self) -> Self {
        self.xhwid = None;
        self
    }

    /// Take the id as text, the way a flag or a config file has it: sixteen
    /// characters to send one, [`HWID_NONE`] to send none, nothing to keep the
    /// default.
    pub fn with_xhwid_text(mut self, given: Option<&str>) -> Result<Self> {
        self.xhwid = XHwid::resolve(given)?;
        Ok(self)
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    pub fn without_stub_cleaning(mut self) -> Self {
        self.clean_stubs = false;
        self
    }

    /// Apply the configured headers (`User-Agent`, `X-Hwid`, custom ones) to
    /// any request, so callers can build their own client.
    pub fn decorate(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut req = builder.header("User-Agent", &self.user_agent);
        // Absent, not empty: a header with nothing in it still says "here is my
        // device id", and that is not what "no id" means.
        if let Some(hwid) = &self.xhwid {
            req = req.header(XHwid::HEADER, hwid.as_str());
        }
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        req
    }
}

/// Download and parse a subscription URL.
pub async fn fetch(url: &str, opts: &FetchOptions) -> Result<Subscription> {
    let client = reqwest::Client::builder()
        .timeout(opts.timeout)
        .danger_accept_invalid_certs(opts.accept_invalid_certs)
        .build()
        .map_err(|e| Error::Fetch(e.to_string()))?;
    let resp = opts
        .decorate(client.get(url))
        .send()
        .await
        .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Fetch(format!(
            "{url}: http {}",
            resp.status().as_u16()
        )));
    }
    let body = read_body(resp, opts.timeout).await?;
    parse_body(&body)
}

/// Read a body that may never end.
///
/// pozor.bond answers 200, streams twelve kilobytes of a perfectly good base64
/// subscription — and then holds the connection open without sending anything
/// more, forever. A reader that waits for the end of the body waits forever too,
/// and the source is written off as dead while it is in fact handing out
/// twenty-nine working configs the whole time.
///
/// So the body is read chunk by chunk with a clock on the silence rather than on
/// the whole transfer: as soon as the server has been quiet for a few seconds,
/// what arrived is what there is. A subscription is a list of independent lines,
/// and a list cut short is still a list.
async fn read_body(resp: reqwest::Response, overall: std::time::Duration) -> Result<String> {
    use futures::StreamExt;

    // Long enough that a slow but working server is not cut off, short enough
    // that a stalled one costs seconds instead of the whole budget.
    let idle = std::cmp::min(
        overall / 4,
        std::time::Duration::from_secs(5),
    )
    .max(std::time::Duration::from_millis(500));
    let mut stream = resp.bytes_stream();
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(chunk))) => buffer.extend_from_slice(&chunk),
            Ok(Some(Err(e))) => return Err(Error::Fetch(e.to_string())),
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if buffer.is_empty() {
        return Err(Error::Fetch("пустой ответ".into()));
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// Download several subscriptions and merge them (dedup + stub cleaning).
pub async fn fetch_many(urls: &[String], opts: &FetchOptions) -> Result<Vec<Node>> {
    let mut all = Vec::new();
    let mut failed = Vec::new();
    for url in urls {
        match fetch(url, opts).await {
            Ok(sub) => all.extend(sub.nodes()),
            Err(e) => {
                tracing::warn!("{e}");
                failed.push(url.clone());
            }
        }
    }
    if all.is_empty() && !failed.is_empty() {
        return Err(Error::Fetch(format!(
            "all {} subscriptions failed, first: {}",
            failed.len(),
            failed[0]
        )));
    }
    let all = crate::filter::dedup(all);
    Ok(if opts.clean_stubs {
        stubs::clean_with(all, &opts.stub_filter)
    } else {
        all
    })
}

/// Encode a node list the way subscription providers do (base64 links).
pub fn encode_links(nodes: &[Node]) -> Result<String> {
    let text = links::render_all(nodes)?;
    Ok(crate::util::b64_string(text.as_bytes()))
}

/// The metadata a subscription can carry above its links.
///
/// This is the "generic subscription" shape that providers publish and clients
/// read: a header block of `#name: value` lines, then plain links. It exists
/// because these fields have nowhere else to go — a client that reads only the
/// body has no way to learn the profile's name, an expiry date or a support
/// URL otherwise.
///
/// Header names are written lowercase with a space after the colon, matching
/// what providers actually serve. Clients key off the name, not the spacing, but
/// matching the convention costs nothing and keeps the output recognisable.
#[derive(Clone, Debug, Default)]
pub struct Headers {
    /// Profile name in the client. Base64 in some providers, plain in others;
    /// clients are expected to take either, so this is passed through as given.
    pub title: Option<String>,
    /// `expire=<unix ts>; total=<bytes>; used=<bytes>`.
    pub user_info: Option<String>,
    /// Short description shown by the client.
    pub announce: Option<String>,
    pub support_url: Option<String>,
    pub web_page_url: Option<String>,
    /// Refresh interval in hours.
    pub update_interval: Option<u32>,
}

impl Headers {
    /// Build a header block with the title and an expiry, the two fields every
    /// client actually reads.
    pub fn titled(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Default::default()
        }
    }

    /// Never-expire user info, which is the honest value for a self-hosted
    /// subscription that is rebuilt from scratch rather than metered.
    pub fn with_unlimited(&mut self) -> &mut Self {
        self.user_info = Some("expire=0; total=0; used=0".into());
        self
    }

    /// The block as `#name: value` lines, each newline-terminated.
    ///
    /// Values are kept on one line: a header parser splits on newlines, and a
    /// title carrying one would end up as two half-parsed fields.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, value) in [
            ("profile-title", &self.title),
            ("announce", &self.announce),
            ("support-url", &self.support_url),
            ("profile-web-page-url", &self.web_page_url),
            ("subscription-userinfo", &self.user_info),
        ] {
            if let Some(value) = value {
                out.push_str(&format!("#{name}: {}\n", one_line(value)));
            }
        }
        if let Some(hours) = self.update_interval {
            out.push_str(&format!("#profile-update-interval: {hours}\n"));
        }
        out
    }

    /// The same fields as HTTP headers, for a server that hands them out.
    ///
    /// The title is base64 there: the HTTP header has to survive non-ASCII,
    /// and every provider base64s it. Clients that see a plain string in this
    /// header show mojibake.
    pub fn as_http(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(title) = &self.title {
            out.push((
                "Profile-Title",
                crate::util::b64_string(title.as_bytes()),
            ));
        }
        if let Some(info) = &self.user_info {
            out.push(("Subscription-Userinfo", one_line(info)));
        }
        if let Some(announce) = &self.announce {
            out.push((
                "Profile-Announce",
                crate::util::b64_string(announce.as_bytes()),
            ));
        }
        if let Some(url) = &self.support_url {
            out.push(("Support-Url", one_line(url)));
        }
        if let Some(url) = &self.web_page_url {
            out.push(("Profile-Web-Page-Url", one_line(url)));
        }
        if let Some(hours) = self.update_interval {
            out.push(("Profile-Update-Interval", hours.to_string()));
        }
        out
    }
}

/// Collapse a value onto one line, since a header field cannot contain a break.
fn one_line(value: &str) -> String {
    value.replace(['\r', '\n'], " ").trim().to_string()
}

/// Render a generic subscription: header block, then one link per line.
///
/// Plain by default, because the header block has to stay readable — that is the
/// point of the format. `wrap_base64` base64s the whole thing for clients that
/// expect an encoded body and would otherwise try to parse the header block as a
/// link.
pub fn render_generic(nodes: &[Node], headers: &Headers) -> Result<String> {
    render_generic_with(nodes, headers, false)
}

/// As [`render_generic`], with the encoded variant available.
///
/// `wrap_base64` is a per-call choice rather than a field on [`Headers`]: the
/// headers describe the subscription, and whether the body is encoded is a
/// property of who is reading it.
pub fn render_generic_with(
    nodes: &[Node],
    headers: &Headers,
    wrap_base64: bool,
) -> Result<String> {
    let mut text = headers.render();
    text.push_str(&links::render_all(nodes)?);
    Ok(if wrap_base64 {
        crate::util::b64_string(text.as_bytes())
    } else {
        text
    })
}

/// Read the header block back off a body, and return it with the node links.
///
/// Providers and clients both need this, and doing it in one place keeps the
/// two halves consistent: the field names written by [`Headers::render`] are the
/// ones [`GenericBody::headers`] recognises.
pub fn parse_generic(body: &str) -> GenericBody {
    let mut headers = Headers::default();
    let mut links = Vec::new();
    let mut saw_header = false;

    for line in body.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('#') {
            let rest = rest.trim_start();
            let Some((name, value)) = rest.split_once(':') else {
                continue;
            };
            let value = value.trim();
            let name = name.trim().to_ascii_lowercase();
            saw_header = true;
            match name.as_str() {
                "profile-title" => headers.title = Some(value.to_string()),
                "announce" => headers.announce = Some(value.to_string()),
                "support-url" => headers.support_url = Some(value.to_string()),
                "profile-web-page-url" => headers.web_page_url = Some(value.to_string()),
                "profile-update-interval" => {
                    headers.update_interval = value.parse().ok();
                }
                "subscription-userinfo" => headers.user_info = Some(value.to_string()),
                // Any other `#` line is a comment, not a field.
                _ => {}
            }
        } else if !line.is_empty() && !line.starts_with("//") {
            links.push(line.to_string());
        }
    }

    GenericBody {
        headers,
        links,
        had_headers: saw_header,
    }
}

/// A parsed generic subscription body.
#[derive(Clone, Debug, Default)]
pub struct GenericBody {
    pub headers: Headers,
    /// The link lines, verbatim, in order.
    pub links: Vec<String>,
    /// Whether any `#name: value` field was present.
    ///
    /// Separate from `headers` being non-empty because a client deciding between
    /// "generic subscription" and "base64 links" needs to know the block was
    /// really there, not merely that some field happened to be empty.
    pub had_headers: bool,
}

/// Re-encode a config as a base64 subscription payload.
pub fn encode_config(bundle: &Bundle, format: Format) -> Result<String> {
    let text = config::render(
        format,
        &bundle.nodes,
        Some(&config::BalancerSpec::new(
            "auto",
            config::BalancerKind::UrlTest,
        )),
    )?;
    Ok(crate::util::b64_string(text.as_bytes()))
}
