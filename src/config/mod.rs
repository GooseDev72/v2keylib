//! Client configuration formats: XRay JSON, sing-box JSON, mihomo YAML.
//!
//! All three are parsed into a [`Bundle`] (a flat list of [`Node`]s plus the
//! balancer groups that referenced them) and rendered back from it.

pub mod mihomo;
pub mod singbox;
pub mod xray;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::node::Node;

/// Balancer / proxy-group behaviour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalancerKind {
    RoundRobin,
    Random,
    LeastPing,
    LeastLoad,
    UrlTest,
    Selector,
    Fallback,
}

impl BalancerKind {
    /// XRay naming (`random`, `roundRobin`, `leastPing`, `leastLoad`).
    ///
    /// XRay has no `url-test` strategy: health probing *is* `leastPing`
    /// (`infra/conf/router.go` accepts exactly these four). Mapping url-test to
    /// `random` would silently drop the probing semantics, so it maps to
    /// `leastPing` instead, which is the closest real equivalent.
    pub fn xray_name(&self) -> &'static str {
        match self {
            BalancerKind::RoundRobin => "roundRobin",
            BalancerKind::Random => "random",
            BalancerKind::LeastPing => "leastPing",
            BalancerKind::LeastLoad => "leastLoad",
            BalancerKind::UrlTest => "leastPing",
            BalancerKind::Selector => "roundRobin",
            BalancerKind::Fallback => "leastPing",
        }
    }

    /// The XRay strategy this maps to, for callers that want to tell the user.
    pub fn xray_kind(&self) -> Option<BalancerKind> {
        BalancerKind::parse(self.xray_name())
    }

    /// sing-box outbound `type`.
    pub fn singbox_name(&self) -> &'static str {
        match self {
            BalancerKind::RoundRobin => "urltest",
            BalancerKind::Random => "random",
            BalancerKind::LeastPing => "urltest",
            BalancerKind::LeastLoad => "urltest",
            BalancerKind::UrlTest => "urltest",
            BalancerKind::Selector => "selector",
            BalancerKind::Fallback => "fallback",
        }
    }

    /// mihomo proxy-group `type`.
    pub fn mihomo_name(&self) -> &'static str {
        match self {
            BalancerKind::RoundRobin => "load-balance",
            BalancerKind::Random => "url-test",
            BalancerKind::LeastPing => "url-test",
            BalancerKind::LeastLoad => "load-balance",
            BalancerKind::UrlTest => "url-test",
            BalancerKind::Selector => "select",
            BalancerKind::Fallback => "fallback",
        }
    }

    /// Accepts both client spellings (`url-test`, `roundrobin`, `leastPing`...).
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().replace(['-', '_'], "").as_str() {
            "roundrobin" | "roundrobin2" | "loadbalance" => Some(BalancerKind::RoundRobin),
            "random" | "random2" => Some(BalancerKind::Random),
            "leastping" => Some(BalancerKind::LeastPing),
            "leastload" => Some(BalancerKind::LeastLoad),
            "urltest" => Some(BalancerKind::UrlTest),
            "select" | "selector" => Some(BalancerKind::Selector),
            "fallback" => Some(BalancerKind::Fallback),
            _ => None,
        }
    }
}

/// Description of a balancer to render into a client config.
#[derive(Clone, Debug)]
pub struct BalancerSpec {
    pub name: String,
    pub kind: BalancerKind,
    /// Node labels/tags that become balancer members (defaults to all nodes).
    pub members: Vec<String>,
    /// Name of the fallback balancer (XRay `fallbackTag`).
    pub fallback: Option<String>,
    /// Probe URL for url-test style balancers.
    pub url: Option<String>,
    /// Probe interval in seconds.
    pub interval: Option<u64>,
    /// urltest tolerance (percentage).
    pub tolerance: Option<u32>,
    /// mihomo `strategy` for load-balance (`round-robin`, `consistent-hashing`).
    pub strategy: Option<String>,
}

impl BalancerSpec {
    pub fn new(name: impl Into<String>, kind: BalancerKind) -> Self {
        Self {
            name: name.into(),
            kind,
            members: Vec::new(),
            fallback: None,
            url: None,
            interval: None,
            tolerance: None,
            strategy: None,
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn with_members<I: IntoIterator<Item = String>>(mut self, members: I) -> Self {
        self.members = members.into_iter().collect();
        self
    }
}

/// A balancer/proxy-group found in a source config.
#[derive(Clone, Debug)]
pub struct Group {
    pub name: String,
    pub kind: BalancerKind,
    /// Member tags as written in the config.
    pub members: Vec<String>,
    pub fallback: Option<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
}

/// Everything recovered from one config document.
#[derive(Clone, Debug, Default)]
pub struct Bundle {
    pub nodes: Vec<Node>,
    pub groups: Vec<Group>,
}

impl Bundle {
    pub fn is_balancer(&self) -> bool {
        !self.groups.is_empty()
    }

    /// Resolve group member tags into concrete nodes.
    pub fn resolve(&self, group: &Group) -> Vec<Node> {
        self.nodes
            .iter()
            .filter(|n| {
                let tag = n.label.clone().unwrap_or_default();
                group.members.contains(&tag)
            })
            .cloned()
            .collect()
    }
}

/// Supported configuration formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    XrayJson,
    SingBoxJson,
    MihomoYaml,
}

impl Format {
    pub fn as_str(&self) -> &'static str {
        match self {
            Format::XrayJson => "xray-json",
            Format::SingBoxJson => "sing-box-json",
            Format::MihomoYaml => "mihomo-yaml",
        }
    }
}

/// Parse a config document, auto-detecting the format.
pub fn parse(input: &str) -> Result<Bundle> {
    parse_merged(input, detect(input)?)
}

pub fn parse_as(input: &str, format: Format) -> Result<Bundle> {
    match format {
        Format::XrayJson => xray::parse(input),
        Format::SingBoxJson => singbox::parse(input),
        Format::MihomoYaml => mihomo::parse(input),
    }
}

/// Some providers ship a JSON array of configs; merge them into one bundle.
pub fn parse_merged(input: &str, format: Format) -> Result<Bundle> {
    let trimmed = input.trim_start();
    if matches!(format, Format::XrayJson | Format::SingBoxJson) && trimmed.starts_with('[') {
        let docs: Vec<serde_json::Value> = serde_json::from_str(input)?;
        let mut bundle = Bundle::default();
        let mut ok = false;
        for doc in docs {
            let text = serde_json::to_string(&doc)?;
            match parse_as(&text, format) {
                Ok(b) => {
                    ok = true;
                    bundle.nodes.extend(b.nodes);
                    bundle.groups.extend(b.groups);
                }
                Err(e) => tracing::debug!("skipping config in array: {e}"),
            }
        }
        if ok {
            return Ok(bundle);
        }
    }
    parse_as(input, format)
}

/// Guess the format from the document shape.
pub fn detect(input: &str) -> Result<Format> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let value: Value = serde_json::from_str(input)?;
        return detect_json(&value);
    }
    if trimmed.contains("proxies:") || trimmed.contains("proxy-groups:") || trimmed.contains("proxies :")
    {
        return Ok(Format::MihomoYaml);
    }
    Err(Error::Detection)
}

fn detect_json(value: &Value) -> Result<Format> {
    if let Some(first) = value.as_array().and_then(|a| a.first()) {
        return detect_json(first);
    }
    let obj = value.as_object().ok_or(Error::Detection)?;
    if obj.contains_key("outbounds") || obj.contains_key("inbounds") {
        // sing-box uses `outbounds[].type` and `server`, xray uses `protocol` + `settings`
        let has_singbox = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter().any(|o| {
                    o.get("type").is_some() && (o.get("server").is_some() || o.get("server_port").is_some())
                })
            })
            .unwrap_or(false);
        return Ok(if has_singbox {
            Format::SingBoxJson
        } else {
            Format::XrayJson
        });
    }
    Err(Error::Detection)
}

/// Describe why `node` cannot be represented in `format`, if it cannot.
///
/// Rendering a node into a format that has no equivalent for one of its
/// settings produces a config that looks fine and fails on the wire with no
/// visible error, so this is checked instead of silently dropping the field.
pub fn unrepresentable(format: Format, node: &Node) -> Option<String> {
    let t = &node.transport;
    let masquerade = t
        .header_type
        .as_deref()
        .map(|h| !h.is_empty() && h != "none")
        .unwrap_or(false);

    match format {
        // Current XRay releases implement Hysteria2 as the `hysteria` outbound
        // with `version: 2`; only the v1 protocol and the obfuscators XRay does
        // not know are left out. XRay refuses the whole file when it meets a
        // protocol it cannot build, not just the one node, so those still have
        // to be filtered before rendering.
        Format::XrayJson => match node.protocol {
            crate::node::Protocol::Hysteria => Some(format!(
                "{}: XRay-core only implements Hysteria2, not Hysteria v1",
                node.socket_addr()
            )),
            crate::node::Protocol::Hysteria2
                if node
                    .obfs
                    .as_deref()
                    .map(|o| !o.is_empty() && !o.eq_ignore_ascii_case("salamander"))
                    .unwrap_or(false) =>
            {
                Some(format!(
                    "{}: XRay-core does not implement hysteria2 obfs={}",
                    node.socket_addr(),
                    node.obfs.as_deref().unwrap_or_default()
                ))
            }
            _ => None,
        },
        // neither core has a VLESS equivalent of XRay's raw-tcp header
        // masquerade: sing-box' `vless` has no `obfs`, mihomo's has no
        // `network: tcp` header at all
        Format::SingBoxJson | Format::MihomoYaml => match t.kind {
            crate::node::TransportKind::Tcp if masquerade => Some(format!(
                "{}: tcp headerType={} has no sing-box/mihomo equivalent",
                node.socket_addr(),
                t.header_type.as_deref().unwrap_or("http"),
            )),
            _ => None,
        },
    }
}

/// Fail if any node would lose settings in `format`. See [`unrepresentable`].
pub fn check_representable(format: Format, nodes: &[Node]) -> Result<()> {
    if let Some(problem) = nodes
        .iter()
        .find_map(|node| unrepresentable(format, node))
    {
        return Err(Error::Unrepresentable(format!(
            "cannot render as {format:?}: {problem}"
        )));
    }
    Ok(())
}

/// Render nodes (and optionally a balancer) into the target format.
///
/// Rejects nodes with settings the target format cannot express, rather than
/// emitting a config that silently drops them. Use [`check_representable`]
/// first to test a batch without rendering it.
pub fn render(format: Format, nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<String> {
    check_representable(format, nodes)?;
    match format {
        Format::XrayJson => xray::render(nodes, balancer),
        Format::SingBoxJson => singbox::render(nodes, balancer),
        Format::MihomoYaml => mihomo::render(nodes, balancer),
    }
}

/// Render a subscription: a single node as a plain link, many nodes (or an
/// explicit spec) as a balancer config.
pub fn render_auto(nodes: &[Node], balancer: Option<&BalancerSpec>) -> Result<String> {
    if balancer.is_none() && nodes.len() == 1 {
        return crate::links::render(&nodes[0]);
    }
    render(Format::XrayJson, nodes, balancer)
}

/// Render as a balancer in the given format.
pub fn render_balancer(format: Format, nodes: &[Node], spec: &BalancerSpec) -> Result<String> {
    render(format, nodes, Some(spec))
}

/// `observatory` and `burst` are health checkers, not balancers a user picks
/// from: neither XRay nor mihomo has a proxy-group for them, and counting one as
/// a group would make the subscription report a group the client cannot see.
fn is_observatory(name: &str) -> bool {
    matches!(name, "observatory" | "burst")
}

/// A proxy-group being collected across documents.
struct GroupDraft {
    name: String,
    kind: BalancerKind,
    keys: Vec<String>,
    url: Option<String>,
    interval: Option<u64>,
}

/// Parse a document, or an array of per-group documents, as XRay configs.
///
/// The builder writes `xray.json` as an array because each group gets its own
/// profile. Nothing here merges them: a caller decides what a node and a group
/// mean across documents, and merging tags blindly would be wrong.
fn documents(input: &str) -> Result<Vec<Bundle>> {
    let trimmed = input.trim_start();
    if trimmed.starts_with('[') {
        let docs: Vec<serde_json::Value> = serde_json::from_str(input)?;
        let mut out = Vec::with_capacity(docs.len());
        for doc in docs {
            let text = serde_json::to_string(&doc)?;
            out.push(xray::parse(&text)?);
        }
        Ok(out)
    } else {
        Ok(vec![xray::parse(input)?])
    }
}

/// How many distinct nodes and non-empty groups a config document holds.
///
/// Used for the `{nodes}` and `{groups}` in a subscription's announcement: the
/// numbers should describe what the client is about to receive, not how many
/// times a node happened to appear across the per-group documents.
pub fn summarize(input: &str) -> Result<(usize, usize)> {
    let mut nodes = std::collections::HashSet::new();
    let mut groups = std::collections::BTreeSet::new();
    for bundle in documents(input)? {
        for node in &bundle.nodes {
            nodes.insert(node.strict_key());
        }
        for group in &bundle.groups {
            if !is_observatory(&group.name) && !bundle.resolve(group).is_empty() {
                groups.insert(group.name.clone());
            }
        }
    }
    Ok((nodes.len(), groups.len()))
}

/// Convert an XRay (or sing-box) configuration document to mihomo YAML.
///
/// The builder writes `xray.json` as an array of per-group configs, each
/// carrying its own outbounds and every balancer. Merging them blindly would
/// duplicate every node once per document and mix tags that belong to different
/// documents, so the conversion goes through node identity instead: a node is
/// added once, and a group collects the nodes its own document gave it. The
/// result keeps the group structure of the subscription, which is the whole
/// point of asking for YAML — mihomo users want the same countries and the same
/// entry point, not one flat list.
pub fn xray_to_mihomo(input: &str) -> Result<String> {
    let documents = documents(input)?;

    let mut nodes: Vec<Node> = Vec::new();
    let mut order: Vec<String> = Vec::new();
    let mut seen_nodes: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut groups: Vec<GroupDraft> = Vec::new();
    let mut seen_groups: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for bundle in &documents {
        for node in &bundle.nodes {
            let key = node.strict_key();
            if seen_nodes.insert(key.clone()) {
                order.push(key);
                nodes.push(node.clone());
            }
        }
        for group in &bundle.groups {
            if is_observatory(&group.name) {
                continue;
            }
            // The same node can be listed twice — once per document, once per
            // duplicate outbound — and a group that names one proxy twice is a
            // group mihomo will refuse or reorder. Every key is added once.
            let index = match seen_groups.get(&group.name).copied() {
                Some(index) => index,
                None => {
                    seen_groups.insert(group.name.clone(), groups.len());
                    groups.push(GroupDraft {
                        name: group.name.clone(),
                        kind: group.kind,
                        keys: Vec::new(),
                        url: group.url.clone(),
                        interval: group.interval,
                    });
                    groups.len() - 1
                }
            };
            for key in bundle.resolve(group).iter().map(Node::strict_key) {
                if !groups[index].keys.contains(&key) {
                    groups[index].keys.push(key);
                }
            }
        }
    }

    if nodes.is_empty() {
        return Err(Error::MalformedLink("no nodes to convert".into()));
    }

    let names = Node::unique_names(&nodes);
    let by_key: std::collections::HashMap<&str, &str> = order
        .iter()
        .zip(names.iter())
        .map(|(key, name)| (key.as_str(), name.as_str()))
        .collect();

    let mut proxies = Vec::with_capacity(nodes.len());
    for (node, name) in nodes.iter().zip(names.iter()) {
        let mut proxy = mihomo::node_to_proxy(node, name)?;
        proxy.name = Some(name.clone());
        proxies.push(proxy);
    }

    let mut proxy_groups = Vec::with_capacity(groups.len());
    for draft in groups {
        let members: Vec<String> = draft
            .keys
            .iter()
            .filter_map(|key| by_key.get(key.as_str()).map(|name| name.to_string()))
            .collect();
        if members.is_empty() {
            continue;
        }
        let mut group = mihomo::ProxyGroup {
            name: draft.name,
            kind: draft.kind.mihomo_name().to_string(),
            proxies: members,
            ..Default::default()
        };
        if matches!(
            draft.kind,
            BalancerKind::UrlTest | BalancerKind::LeastPing | BalancerKind::Fallback
        ) {
            group.url = Some(
                draft
                    .url
                    .unwrap_or_else(|| "https://www.gstatic.com/generate_204".into()),
            );
            group.interval = Some(draft.interval.unwrap_or(300));
        }
        proxy_groups.push(group);
    }

    let entry = proxy_groups
        .first()
        .map(|g| g.name.clone())
        .unwrap_or_else(|| "DIRECT".into());
    let cfg = mihomo::MihomoConfig {
        mixed_port: Some(7890),
        allow_lan: Some(false),
        mode: Some("rule".into()),
        proxies,
        proxy_groups,
        rules: vec![serde_yaml::from_str(&format!("MATCH,{entry}")).unwrap()],
        ..Default::default()
    };
    Ok(serde_yaml::to_string(&cfg)?)
}
