//! Building several balancers over one config, and publishing them.
//!
//! ## XRay constraints this design obeys
//!
//! From `app/proxyman/outbound/outbound.go`:
//!
//! ```go
//! func (m *Manager) Select(selectors []string) []string {
//!     for tag := range m.taggedHandler {          // outbound handlers only
//!         for _, selector := range selectors {
//!             if strings.HasPrefix(tag, selector) { // PREFIX match, not exact
//! ```
//!
//! Two consequences:
//!
//! 1. **Balancers cannot be nested.** A balancer tag is not an outbound handler,
//!    so putting one in another balancer's `selector` selects nothing and the
//!    balancer has an empty candidate list (it then falls back or errors). All
//!    balancers here are therefore *siblings* over concrete outbound tags; a
//!    group may narrow another group's members, but it still materialises as its
//!    own balancer with its own tags.
//! 2. **Selectors are prefixes.** `["de"]` also matches `denmark-1`. Full tags
//!    are used and [`Plan::validate`] rejects selectors that would over-capture.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::config::{BalancerKind, BalancerSpec};
use crate::error::{Error, Result};
use crate::node::Node;

/// One balancer to emit.
#[derive(Clone, Debug)]
pub struct Group {
    /// Balancer tag, also its position in the export.
    pub name: String,
    pub kind: BalancerKind,
    /// Indices into the node list, in the order the user chose them.
    pub members: Vec<usize>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u32>,
    /// Optional note kept for the caller's own bookkeeping.
    pub comment: Option<String>,
}

impl Group {
    pub fn new(name: impl Into<String>, kind: BalancerKind, members: Vec<usize>) -> Self {
        Self {
            name: name.into(),
            kind,
            members,
            url: None,
            interval: None,
            tolerance: None,
            comment: None,
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.interval = Some(secs);
        self
    }
}

/// A warning about a plan that will misbehave in XRay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning(pub String);

impl std::fmt::Display for Warning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of building the export.
#[derive(Clone, Debug)]
pub struct Export {
    /// New balancer configs, first, in the order the groups were given.
    pub configs: Vec<Value>,
    /// The balancer tag routing falls back to when nothing else matches.
    pub default_tag: Option<String>,
    pub warnings: Vec<Warning>,
    /// The JSON document, ready to serve.
    pub json: String,
}

/// How outbound tags are derived for the generated configs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TagScheme {
    /// `n00`, `n01`, ... `n42` — zero padded to a common width.
    ///
    /// This is the default because XRay matches selectors by *prefix*: with
    /// equal-width tags no tag can be a prefix of another, so a balancer can
    /// never capture a neighbour. The original name is kept in `remark`.
    #[default]
    Index,
    /// Sanitised node labels (`alpha`, `bravo`, ...). Readable, but only safe
    /// when no tag is a prefix of another — [`Plan::export`] refuses otherwise.
    Label,
}

/// An ordered set of balancers over one node list.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub groups: Vec<Group>,
    pub default: Option<String>,
    pub tag_scheme: TagScheme,
    /// Emit local SOCKS/HTTP inbounds so the config runs standalone.
    ///
    /// Off by default: a profile imported into a client gets its inbounds from
    /// that client, and shipping a second pair there just collides on ports.
    pub inbounds: bool,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_tag_scheme(mut self, scheme: TagScheme) -> Self {
        self.tag_scheme = scheme;
        self
    }

    /// Append a balancer. Consuming, so `Plan::new().with(a).with(b)` chains.
    pub fn with(mut self, group: Group) -> Self {
        self.groups.push(group);
        self
    }

    /// Make the exported config self-contained, with local inbounds.
    pub fn with_inbounds(mut self, yes: bool) -> Self {
        self.inbounds = yes;
        self
    }

    /// In-place variant for building a plan in a loop.
    pub fn push(&mut self, group: Group) -> &mut Self {
        self.groups.push(group);
        self
    }

    /// Tag used for the catch-all routing rule.
    pub fn set_default(mut self, tag: impl Into<String>) -> Self {
        self.default = Some(tag.into());
        self
    }

    pub fn set_default_mut(&mut self, tag: impl Into<String>) -> &mut Self {
        self.default = Some(tag.into());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Tag for node `index` out of `total`, under this plan's scheme.
    pub fn tag_for(&self, node: &Node, index: usize, total: usize) -> String {
        match self.tag_scheme {
            TagScheme::Index => {
                // width of the largest index, so every tag has the same length
                let width = total.saturating_sub(1).to_string().len().max(2);
                format!("n{index:0width$}")
            }
            TagScheme::Label => match node.label.as_deref() {
                Some(label) if !label.is_empty() => sanitize_tag(label, index),
                _ => format!("n{index:0width$}", width = total.max(2).to_string().len()),
            },
        }
    }

    /// All tags, in node order.
    pub fn tags(&self, nodes: &[Node]) -> Vec<String> {
        (0..nodes.len())
            .map(|i| self.tag_for(&nodes[i], i, nodes.len()))
            .collect()
    }

    /// Check the plan before exporting.
    pub fn validate(&self, nodes: &[Node]) -> Vec<Warning> {
        let mut warnings = Vec::new();
        let all_tags = self.tags(nodes);

        let mut names = BTreeSet::new();
        for group in &self.groups {
            if group.name.is_empty() {
                warnings.push(Warning("a balancer has an empty tag".into()));
            }
            if !names.insert(group.name.clone()) {
                warnings.push(Warning(format!(
                    "duplicate balancer tag `{}` — XRay keeps only one",
                    group.name
                )));
            }
            if group.members.is_empty() {
                warnings.push(Warning(format!(
                    "balancer `{}` has no members; XRay needs a non-empty selector",
                    group.name
                )));
            }
            for &i in &group.members {
                if i >= nodes.len() {
                    warnings.push(Warning(format!(
                        "balancer `{}` references index {} but there are only {} nodes",
                        group.name,
                        i + 1,
                        nodes.len()
                    )));
                }
            }
            // prefix-match hazard: a selector that is a prefix of a tag outside
            // this group would silently pull that tag in at runtime.
            for &i in &group.members {
                if i >= nodes.len() {
                    continue;
                }
                let tag = &all_tags[i];
                let pos = nodes
                    .iter()
                    .position(|n| self.tag_for(n, 0, nodes.len()) == *tag);
                let _ = pos;
                let outside: Vec<&String> = all_tags
                    .iter()
                    .filter(|t| t.as_str() != tag.as_str())
                    .filter(|t| t.starts_with(tag.as_str()))
                    .collect();
                if !outside.is_empty() {
                    warnings.push(Warning(format!(
                        "balancer `{}`: tag `{tag}` is a prefix of {:?}; XRay selectors match by prefix and would capture them",
                        group.name,
                        outside
                    )));
                }
            }
        }

        if let Some(default) = &self.default {
            if !names.contains(default) {
                warnings.push(Warning(format!(
                    "default balancer `{default}` is not defined in this plan"
                )));
            }
        }
        warnings
    }

    /// Build the export.
    ///
    /// `original` configs from the source subscription are preserved and
    /// appended *after* the new balancer configs, so a client that reads the
    /// array in order uses the balancers first.
    pub fn export(&self, nodes: &[Node], original: &[Value]) -> Result<Export> {
        let warnings = self.check(nodes)?;
        let tags = self.tags(nodes);

        let mut configs = Vec::new();
        for (order, (group, members)) in self
            .groups
            .iter()
            .zip(self.resolve_members(nodes, &tags)?)
            .enumerate()
        {
            let spec = self.spec_for(group, members.clone());
            let mut config = crate::config::xray::export_config_tagged(nodes, &tags, Some(&spec))?;
            if self.inbounds {
                config["inbounds"] = crate::config::xray::default_inbounds();
            }
            crate::config::xray::set_name(
                &mut config,
                &group.comment.clone().unwrap_or_else(|| {
                    format!("{} ({} of {})", group.name, members.len(), nodes.len())
                }),
            );
            config["order"] = json!(order);
            configs.push(config);
        }

        let default_tag = Some(self.default_tag());
        let mut all = configs.clone();
        all.extend(original.iter().cloned());
        let json = serde_json::to_string_pretty(&all)?;

        Ok(Export {
            configs,
            default_tag,
            warnings,
            json,
        })
    }

    /// Put **every** balancer into one XRay config.
    ///
    /// [`Plan::export`] emits one config per balancer, which is what a client
    /// wants when each profile is a separate switch. This variant instead
    /// builds a single config carrying all balancers, so routing rules can
    /// choose between them inside one profile — the usual shape for
    /// "Авто / Авто-БС / Финляндия / Латвия / ..." subscriptions.
    pub fn export_single(&self, nodes: &[Node], original: &[Value]) -> Result<SingleExport> {
        let warnings = self.check(nodes)?;
        let tags = self.tags(nodes);
        let members = self.resolve_members(nodes, &tags)?;

        let mut config = crate::config::xray::export_config_tagged(nodes, &tags, None)?;
        let balancers: Vec<Value> = self
            .groups
            .iter()
            .zip(members.iter())
            .map(|(group, m)| {
                let spec = self.spec_for(group, m.clone());
                crate::config::xray::balancer_object(&spec, m, nodes.len())
            })
            .collect();

        if self.inbounds {
            config["inbounds"] = crate::config::xray::default_inbounds();
        }

        // A latency strategy has nothing to rank on unless something measures
        // the outbounds: XRay feeds `leastPing` from an observatory handler, and
        // a config that declares one without any is asking for the strategy to
        // pick blind. Publish one covering every node, so each balancer can draw
        // on the whole pool rather than only its own slice.
        if self.needs_observatory() {
            let probe = self
                .groups
                .iter()
                .find_map(|g| g.url.clone())
                .unwrap_or_else(|| "https://cp.cloudflare.com/generate_204".into());
            let interval = self
                .groups
                .iter()
                .find_map(|g| g.interval)
                .unwrap_or(crate::config::xray::DEFAULT_BURST_INTERVAL);
            config["burstObservatory"] =
                crate::config::xray::burst_observatory(&tags, &probe, interval);
        }

        let default_tag = self.default_tag();
        config["routing"] = crate::config::xray::routing_block(
            balancers,
            json!({ "type": "field", "balancerTag": default_tag }),
        );
        // The profile is named after the balancer traffic goes through by
        // default: that is the one a client lists the profile under, and a
        // "3 balancers, 42 outbounds" summary tells the user nothing.
        crate::config::xray::set_name(&mut config, &default_tag);

        let mut all = vec![config.clone()];
        all.extend(original.iter().cloned());
        let json = serde_json::to_string_pretty(&all)?;
        let plain = serde_json::to_string_pretty(&config)?;

        Ok(SingleExport {
            config,
            default_tag,
            warnings,
            json,
            plain,
        })
    }

    /// Shared pre-flight: non-empty, and no prefix collisions.
    fn check(&self, nodes: &[Node]) -> Result<Vec<Warning>> {
        if self.groups.is_empty() {
            return Err(Error::Balancer("plan has no balancers".into()));
        }
        let warnings = self.validate(nodes);
        // A prefix collision makes XRay capture the wrong outbounds, silently.
        // That is worse than a build failure, so refuse.
        if let Some(collision) = warnings.iter().find(|w| w.0.contains("prefix")) {
            return Err(Error::Balancer(format!(
                "{collision}\nUse TagScheme::Index (the default) for collision-free tags"
            )));
        }
        for w in &warnings {
            tracing::warn!("{w}");
        }
        Ok(warnings)
    }

    fn resolve_members(&self, nodes: &[Node], tags: &[String]) -> Result<Vec<Vec<String>>> {
        self.groups
            .iter()
            .map(|group| {
                let members: Vec<String> = group
                    .members
                    .iter()
                    .filter(|&&i| i < nodes.len())
                    .map(|&i| tags[i].clone())
                    .collect();
                if members.is_empty() {
                    return Err(Error::Balancer(format!(
                        "balancer `{}` ended up with no usable members",
                        group.name
                    )));
                }
                Ok(members)
            })
            .collect()
    }

    /// True when at least one balancer ranks by latency or load.
    ///
    /// `random` and `roundRobin` need no measurements, so a plan built only from
    /// those gets no observatory and stays small.
    fn needs_observatory(&self) -> bool {
        self.groups.iter().any(|g| {
            matches!(
                g.kind,
                BalancerKind::LeastPing
                    | BalancerKind::LeastLoad
                    | BalancerKind::UrlTest
                    | BalancerKind::Fallback
            )
        })
    }

    fn spec_for(&self, group: &Group, members: Vec<String>) -> BalancerSpec {
        BalancerSpec {
            name: group.name.clone(),
            kind: group.kind,
            fallback: members.first().cloned(),
            members,
            url: group.url.clone(),
            interval: group.interval,
            tolerance: group.tolerance,
            strategy: None,
        }
    }

    pub fn default_tag(&self) -> String {
        self.default
            .clone()
            .or_else(|| self.groups.first().map(|g| g.name.clone()))
            .unwrap_or_default()
    }
}

/// One config with many balancers.
#[derive(Clone, Debug)]
pub struct SingleExport {
    pub config: Value,
    pub default_tag: String,
    pub warnings: Vec<Warning>,
    /// The array: the built config first, then any original configs.
    pub json: String,
    /// Just the built config, as an object.
    pub plain: String,
}

/// XRay tags must not contain characters that break routing rules.
fn sanitize_tag(label: &str, index: usize) -> String {
    let cleaned: String = label
        .chars()
        .map(|c| {
            // Unicode letters stay: these tags are the names the user reads in
            // the balancer editor, and `🇺🇸 США 01` reduced to `________01` is
            // the same as no name at all. Emoji are dropped — they are not
            // alphanumeric, and XRay matches selectors bytewise, where a flag is
            // four characters of surprise.
            if c.is_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('_').to_string();
    if cleaned.is_empty() {
        format!("proxy-{index}")
    } else {
        cleaned
    }
}

/// Human-readable numbered listing for the interactive constructor.
pub fn numbered_list(nodes: &[Node], limit: usize) -> String {
    let mut out = String::new();
    for (i, node) in nodes.iter().enumerate() {
        if limit > 0 && i >= limit {
            out.push_str(&format!("  ... and {} more\n", nodes.len() - limit));
            break;
        }
        let label = node.label.clone().unwrap_or_default();
        let mut line = format!(
            "{:>4}  {:<7} {:<22} {:<5} {}",
            i + 1,
            node.protocol.as_str(),
            node.socket_addr(),
            node.security.as_str(),
            label
        );
        if !node.sni.as_deref().unwrap_or_default().is_empty() {
            line.push_str(&format!("  sni={}", node.sni.as_deref().unwrap()));
        }
        if node.transport.kind != crate::node::TransportKind::Tcp {
            line.push_str(&format!("  type={}", node.transport.kind.as_str()));
        }
        if node.flow.is_some() {
            line.push_str(&format!("  flow={}", node.flow.as_deref().unwrap_or("")));
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Group nodes by a field, for a quick first cut of a subscription.
pub fn group_by_country(nodes: &[Node]) -> BTreeMap<String, Vec<usize>> {
    let mut out: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, node) in nodes.iter().enumerate() {
        let key = node
            .extra
            .get("country")
            .cloned()
            .unwrap_or_else(|| "??".to_string());
        out.entry(key).or_default().push(i);
    }
    out
}
