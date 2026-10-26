//! Balancer creation and decomposition.

pub mod flatten;
pub mod plan;
pub mod tiers;

use crate::config::{BalancerKind, BalancerSpec, Bundle, Format, Group};
use crate::error::Result;
use crate::links;
use crate::node::Node;

pub use crate::config::{render_balancer, BalancerSpec as Spec};

/// Build a balancer config in `format` from a node list.
pub fn build(
    nodes: &[Node],
    format: Format,
    kind: BalancerKind,
    name: &str,
) -> Result<String> {
    build_with(nodes, format, &BalancerSpec::new(name, kind))
}

/// Build with full control over members, probe url and interval.
pub fn build_with(nodes: &[Node], format: Format, spec: &BalancerSpec) -> Result<String> {
    crate::config::render(format, nodes, Some(spec))
}

/// Flatten any config (single or balancer) into a flat link list.
///
/// This is the inverse of [`build`]: a subscription that only contains
/// balancers comes back out as individually importable links.
pub fn decompose(bundle: &Bundle) -> Result<String> {
    links::render_all(&bundle.nodes)
}

/// Decompose and keep the group structure, tagging each node with its group.
pub fn decompose_tagged(bundle: &Bundle) -> Vec<(String, Node)> {
    let mut out = Vec::new();
    for (i, node) in bundle.nodes.iter().enumerate() {
        let mut node = node.clone();
        let group = bundle
            .groups
            .iter()
            .find(|g| {
                let tag = node.label.clone().unwrap_or_default();
                g.members.contains(&tag)
            })
            .map(|g| g.name.clone())
            .unwrap_or_else(|| "default".into());
        if node.label.is_none() {
            node.label = Some(format!("{}-{}", group, i));
        }
        out.push((group, node));
    }
    out
}

/// Re-derive a [`BalancerSpec`] from a parsed group.
pub fn spec_from_group(group: &Group) -> BalancerSpec {
    let mut spec = BalancerSpec::new(group.name.clone(), group.kind);
    spec.members = group.members.clone();
    spec.fallback = group.fallback.clone();
    spec.url = group.url.clone();
    spec.interval = group.interval;
    spec
}

/// Nodes of a specific group, by tag.
pub fn group_nodes(bundle: &Bundle, group_name: &str) -> Vec<Node> {
    match bundle.groups.iter().find(|g| g.name == group_name) {
        Some(group) => bundle.resolve(group),
        None => Vec::new(),
    }
}
