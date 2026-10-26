//! Flattening: every balancer and group turned into standalone pieces.
//!
//! A balancer config is convenient for the client that reads balancers and
//! useless to everything else — you cannot put a delay on "автовыбор", you
//! cannot import it as a list, and you cannot see which node is which. This
//! module is the way out: every group becomes its own set of flat entries,
//! one per node, named so they stay apart once they are apart.
//!
//! ```no_run
//! # fn main() -> v2keylib::Result<()> {
//! let bundle = v2keylib::config::parse(&std::fs::read_to_string("sub.json")?)?;
//!
//! // every node of every group, as links you can import one by one
//! let links = v2keylib::balancer::flatten::to_links(&bundle)?;
//!
//! // or as standalone configs, in whichever format the client reads
//! let configs = v2keylib::balancer::flatten::to_configs(&bundle, v2keylib::config::Format::XrayJson)?;
//! for c in &configs {
//!     println!("{}: {} bytes", c.flat.tag, c.config.len());
//! }
//! # Ok(())
//! # }
//! ```

use crate::config::{Bundle, Format, Group};
use crate::error::Result;
use crate::links;
use crate::node::Node;
use std::collections::BTreeSet;

/// The group a node belonged to nothing of.
pub const NO_GROUP: &str = "ungrouped";

/// One node, out of its balancer, ready to stand alone.
#[derive(Clone, Debug)]
pub struct Flat {
    /// The group it came from; [`NO_GROUP`] when it came from none.
    pub group: String,
    /// The balancer that group was, if it was one.
    pub kind: Option<crate::config::BalancerKind>,
    /// Position inside the group, counting from one.
    pub index: usize,
    /// How many nodes the group had, so a caller can lay the list out.
    pub total: usize,
    /// The name this piece carries once it is alone: `<group>-<n>`.
    pub tag: String,
    /// The node itself, relabelled to [`Flat::tag`].
    pub node: Node,
}

/// One rendered document, with the flat entry it came from.
#[derive(Clone, Debug)]
pub struct FlatConfig {
    pub flat: Flat,
    /// The rendered document: JSON for the json formats, YAML for mihomo.
    pub config: String,
}

/// Every node of every group, groups in config order, nodes in config order.
///
/// Two decisions worth stating outright:
///
/// * a node that sits in more than one group is emitted once, under the first
///   group that claims it — the alternative is the same node twice in a list
///   someone is about to import, which is noise, not information;
/// * a node in no group at all is emitted too, under [`NO_GROUP`]. Dropping it
///   would be the one genuinely lossy thing this could do.
pub fn flatten(bundle: &Bundle) -> Vec<Flat> {
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut out: Vec<Flat> = Vec::new();

    for group in &bundle.groups {
        let members = members_with_index(bundle, group);
        if members.is_empty() {
            continue;
        }
        let total = members.len();
        let width = width_of(total);
        for (i, (idx, mut node)) in members.into_iter().enumerate() {
            if !seen.insert(idx) {
                continue;
            }
            let tag = numbered(&group.name, i + 1, width);
            node.label = Some(tag.clone());
            out.push(Flat {
                group: group.name.clone(),
                kind: Some(group.kind),
                index: i + 1,
                total,
                tag,
                node,
            });
        }
    }

    let orphans: Vec<(usize, Node)> = bundle
        .nodes
        .iter()
        .enumerate()
        .filter(|(idx, _)| !seen.contains(idx))
        .map(|(idx, node)| (idx, node.clone()))
        .collect();
    if !orphans.is_empty() {
        let total = orphans.len();
        let width = width_of(total);
        for (i, (_, mut node)) in orphans.into_iter().enumerate() {
            let tag = numbered(NO_GROUP, i + 1, width);
            node.label = Some(tag.clone());
            out.push(Flat {
                group: NO_GROUP.to_string(),
                kind: None,
                index: i + 1,
                total,
                tag,
                node,
            });
        }
    }

    out
}

/// The group's members as `(index in the bundle, node)`.
///
/// The index is what makes "already emitted" answerable: a node is an entry in
/// `bundle.nodes`, and the same endpoint may legitimately sit there twice — two
/// outbounds that differ only in a path are two nodes to a client, and only one
/// of them belongs to this group.
fn members_with_index(bundle: &Bundle, group: &Group) -> Vec<(usize, Node)> {
    bundle
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            let tag = node.label.clone().unwrap_or_default();
            group.members.contains(&tag)
        })
        .map(|(idx, node)| (idx, node.clone()))
        .collect()
}

/// The flattened nodes as a link list, one link per line, named by group.
///
/// This is [`super::decompose`] with the group structure kept: two nodes that
/// shared a name across groups stay apart here.
pub fn to_links(bundle: &Bundle) -> Result<String> {
    let nodes: Vec<Node> = flatten(bundle).into_iter().map(|f| f.node).collect();
    links::render_all(&nodes)
}

/// The flattened nodes as standalone configs in `format`, one per node.
///
/// A node that cannot be rendered in that format is skipped rather than
/// sinking the rest: an mihomo profile cannot carry every protocol a vless
/// balancer can, and that is a reason to leave it out, not to fail.
pub fn to_configs(bundle: &Bundle, format: Format) -> Result<Vec<FlatConfig>> {
    let mut out = Vec::new();
    for flat in flatten(bundle) {
        match crate::config::render(format, std::slice::from_ref(&flat.node), None) {
            Ok(config) => out.push(FlatConfig { flat, config }),
            Err(e) => tracing::warn!("{}: cannot render as {}: {e}", flat.tag, format.as_str()),
        }
    }
    Ok(out)
}

/// The groups as one config each, in `format`.
///
/// The step short of [`to_configs`]: still one switchable thing per group, but
/// with the balancer gone — a group is now a plain list of the nodes it had.
pub fn groups_to_configs(bundle: &Bundle, format: Format) -> Result<Vec<FlatConfig>> {
    let mut out = Vec::new();
    for group in &bundle.groups {
        let members = bundle.resolve(group);
        if members.is_empty() {
            continue;
        }
        match crate::config::render(format, &members, None) {
            Ok(config) => out.push(FlatConfig {
                flat: Flat {
                    group: group.name.clone(),
                    kind: Some(group.kind),
                    index: 1,
                    total: members.len(),
                    tag: group.name.clone(),
                    node: members[0].clone(),
                },
                config,
            }),
            Err(e) => tracing::warn!("{}: cannot render as {}: {e}", group.name, format.as_str()),
        }
    }
    Ok(out)
}

/// `<group>-<n>`, zero-padded to the width of the group's size so a list of
/// them sorts the way a person reads it.
fn numbered(group: &str, index: usize, width: usize) -> String {
    format!("{group}-{index:0width$}")
}

/// Two digits unless the group is bigger, so `01..09` and `10` do not sort
/// wrong against each other.
fn width_of(total: usize) -> usize {
    total.to_string().len().max(2)
}
