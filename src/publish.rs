//! Publishing a subscription in the shape providers expect.

use serde_json::{json, Value};

use crate::config::{self, BalancerKind, BalancerSpec, Format};
use crate::error::{Error, Result};
use crate::filter::stubs::{self, StubFilter};
use crate::node::Node;

/// How the fetched nodes should be served back.
#[derive(Clone, Debug)]
pub enum Output {
    /// Plain `vless://`-style links, newline separated.
    Links,
    /// Base64 of the link list (what most panels serve).
    LinksBase64,
    /// One XRay config with every outbound and no balancer.
    XrayJson,
    /// XRay config with a single balancer over every node.
    XrayJsonBalancer,
    /// A JSON *array* with one config per node — the HAPPiVPN shape.
    XrayJsonArray,
    /// A JSON array whose **first** element is a balancer over every node,
    /// followed by the per-node configs.
    XrayJsonBalancerFirst,
    /// Same, but base64-encoded (how panels actually deliver configs).
    Base64Of(Box<Output>),
}

impl Output {
    pub fn balancer_first() -> Self {
        Output::XrayJsonBalancerFirst
    }

    fn unwrap(&self) -> &Output {
        match self {
            Output::Base64Of(inner) => inner.unwrap(),
            other => other,
        }
    }

    fn is_base64(&self) -> bool {
        matches!(self, Output::Base64Of(_))
    }
}

/// Options for rendering a subscription body.
#[derive(Clone, Debug)]
pub struct PublishOptions {
    pub output: Output,
    /// Balancer tag for the single-balancer outputs.
    pub balancer_name: String,
    pub balancer_kind: BalancerKind,
    pub probe_url: Option<String>,
    pub probe_interval: Option<u64>,
    pub tolerance: Option<u32>,
    /// Base64 (vs plain) for the balancer-first output.
    pub plain: bool,
}

impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            output: Output::XrayJsonBalancerFirst,
            balancer_name: "auto".into(),
            balancer_kind: BalancerKind::UrlTest,
            probe_url: None,
            probe_interval: None,
            tolerance: None,
            plain: false,
        }
    }
}

/// Where the nodes came from, so `extra` marks survive.
#[derive(Clone, Debug, Default)]
pub struct Published {
    pub body: String,
    pub used_nodes: usize,
    pub dropped_stubs: usize,
}

/// Render nodes into a subscription body.
pub fn publish(nodes: &[Node], opts: &PublishOptions) -> Result<Published> {
    if nodes.is_empty() {
        return Err(Error::MalformedLink("nothing to publish".into()));
    }
    let (kept, removed) = stubs::partition(nodes.to_vec(), &StubFilter::default());
    let dropped = removed.len();
    let nodes = if kept.is_empty() { nodes.to_vec() } else { kept };

    let body = render_output(&nodes, opts)?;
    Ok(Published {
        body,
        used_nodes: nodes.len(),
        dropped_stubs: dropped,
    })
}

fn render_output(nodes: &[Node], opts: &PublishOptions) -> Result<String> {
    match opts.output.unwrap() {
        Output::Links => crate::links::render_all(nodes),
        Output::LinksBase64 => crate::subscription::encode_links(nodes),
        Output::XrayJson => config::render(Format::XrayJson, nodes, None),
        Output::XrayJsonBalancer => {
            let spec = spec_from(opts, &all_tags(nodes))?;
            config::render(Format::XrayJson, nodes, Some(&spec))
        }
        Output::XrayJsonArray => {
            let array = array_configs(nodes, None)?;
            Ok(serde_json::to_string_pretty(&array)?)
        }
        Output::XrayJsonBalancerFirst => {
            let spec = spec_from(opts, &all_tags(nodes))?;
            let mut array = array_configs(nodes, Some(&spec))?;
            if array.is_empty() {
                return Err(Error::MalformedLink("no configs produced".into()));
            }
            // the balancer config goes first, and must come before the
            // per-node configs in the array
            let head = array.remove(0);
            let head_tag = spec.name.clone();
            array.insert(0, decorate_head(head, &head_tag, nodes.len()));
            let text = serde_json::to_string_pretty(&array)?;
            if opts.output.is_base64() {
                Ok(crate::util::b64_string(text.as_bytes()))
            } else {
                Ok(text)
            }
        }
        Output::Base64Of(_) => unreachable!("unwrapped above"),
    }
}

fn spec_from(opts: &PublishOptions, tags: &[String]) -> Result<BalancerSpec> {
    if tags.is_empty() {
        return Err(Error::Balancer("no outbounds to balance".into()));
    }
    let mut spec = BalancerSpec::new(opts.balancer_name.clone(), opts.balancer_kind)
        .with_members(tags.to_vec());
    if opts.probe_url.is_some() {
        spec.url = opts.probe_url.clone();
    }
    spec.interval = opts.probe_interval;
    spec.tolerance = opts.tolerance;
    Ok(spec)
}

/// Default plan used for tags here: the collision-free index scheme.
fn default_plan() -> crate::balancer::plan::Plan {
    crate::balancer::plan::Plan::new()
}

fn all_tags(nodes: &[Node]) -> Vec<String> {
    default_plan().tags(nodes)
}

/// One config per node, each standalone, optionally preceded by a balancer
/// config over all of them.
fn array_configs(nodes: &[Node], spec: Option<&BalancerSpec>) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        let tag = crate::balancer::plan::Plan::new().tag_for(node, i, nodes.len());
        let mut ob = config::xray::outbound_for(node, &tag);
        let name = node.label.clone().unwrap_or_else(|| tag.clone());
        if let Value::Object(map) = &mut ob {
            map.insert("remark".into(), json!(name.clone()));
        }
        // `remarks`, not `remark`: it is the key a subscription entry is listed
        // under, and an entry without one shows up unnamed in the client.
        out.push(json!({
            "remarks": name,
            "outbounds": [ob],
        }));
    }
    if let Some(spec) = spec {
        // prepended; array_configs returns per-node configs, so the balancer
        // config is built separately and pushed by the caller
        let balancer = config::xray::export_config(nodes, Some(spec))?;
        let mut with_head = vec![balancer];
        with_head.extend(out);
        return Ok(with_head);
    }
    Ok(out)
}

fn decorate_head(mut head: Value, tag: &str, count: usize) -> Value {
    config::xray::set_name(&mut head, &format!("{tag} — balancer over {count} configs"));
    head
}

/// Re-encode a bundle that was parsed from a provider, preserving the original
/// config array and putting freshly built balancers in front of it.
pub fn publish_bundle(
    bundle: &crate::config::Bundle,
    original: &[Value],
    opts: &PublishOptions,
) -> Result<String> {
    match opts.output.unwrap() {
        Output::XrayJsonBalancerFirst | Output::XrayJsonArray => {
            let mut head = array_configs(&bundle.nodes, None)?;
            let spec = spec_from(opts, &all_tags(&bundle.nodes))?;
            let balancer = config::xray::export_config(&bundle.nodes, Some(&spec))?;
            head.insert(0, decorate_head(balancer, &spec.name, bundle.nodes.len()));
            head.extend(original.iter().cloned());
            let text = serde_json::to_string_pretty(&head)?;
            Ok(if opts.output.is_base64() {
                crate::util::b64_string(text.as_bytes())
            } else {
                text
            })
        }
        _ => publish(&bundle.nodes, opts).map(|p| p.body),
    }
}
