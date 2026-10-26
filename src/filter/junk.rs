//! Dropping padded and spammy entries from a subscription.
//!
//! A stub is an entry that was never a server. Junk is a real server carrying a
//! query string nobody asked for — a provider's advertising, a padding trick to
//! make a short link look distinctive, or a copy-paste of the same handle a few
//! dozen times. It survives dedup, becomes a first-class balancer member, and
//! changes nothing about whether the node connects.
//!
//! Two shapes matter in practice, both seen in the wild:
//!
//! ```text
//! ?authority=/?telegram--MARAMBASHI--MARAMBASHI--MARAMBASHI--MARAMBASHI
//! ?Telegram=@GozargahAzad,@GozargahAzad,@GozargahAzad,@GozargahAzad
//! ```
//!
//! The first repeats one token; the second repeats one handle. Neither is a
//! parameter any client reads — `Telegram` is not part of any link format this
//! library models — so both are droppable without knowing what they advertise.

use std::collections::HashMap;

use crate::node::Node;

/// Query parameters that carry nothing a client can use.
///
/// Matched case-insensitively against the parameter name.
pub const DEFAULT_JUNK_PARAMS: &[&str] = &[
    "telegram",
    "twitter",
    "t.me",
];

/// Substrings that mark a padded value wherever they appear.
pub const DEFAULT_JUNK_MARKERS: &[&str] = &[
    "telegram--",
    "/%3F",
    "%2F%3F",
];

/// How many times one token may repeat in a single value before it is junk.
pub const DEFAULT_MAX_REPEAT: usize = 3;

/// What counts as junk, and how strictly.
#[derive(Clone, Debug)]
pub struct JunkFilter {
    /// Parameter names that disqualify a node outright.
    pub drop_params: Vec<String>,
    /// Substrings that disqualify a node wherever they appear in its query.
    pub drop_markers: Vec<String>,
    /// Repetition ceiling for a single value.
    ///
    /// Zero disables the check, which is what a hand-written link with an
    /// accidental duplicate should get: the other rules still apply.
    pub max_repeat: usize,
}

impl Default for JunkFilter {
    fn default() -> Self {
        Self {
            drop_params: DEFAULT_JUNK_PARAMS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            drop_markers: DEFAULT_JUNK_MARKERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_repeat: DEFAULT_MAX_REPEAT,
        }
    }
}

impl JunkFilter {
    /// Keep nothing: no parameter is junk.
    pub fn permissive() -> Self {
        Self {
            drop_params: Vec::new(),
            drop_markers: Vec::new(),
            max_repeat: 0,
        }
    }

    /// Why this node is junk, if it is.
    ///
    /// Returns the reason rather than a bool because "dropped 40 nodes" is not
    /// actionable — "dropped 40 nodes carrying `?Telegram=`" is.
    pub fn reject(&self, node: &Node) -> Option<String> {
        let query = query_string(node);

        for param in &self.drop_params {
            if query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .any(|(name, _)| name.eq_ignore_ascii_case(param))
            {
                return Some(format!("carries `{param}=`"));
            }
        }

        let lower = query.to_ascii_lowercase();
        for marker in &self.drop_markers {
            if lower.contains(&marker.to_ascii_lowercase()) {
                return Some(format!("query contains `{marker}`"));
            }
        }

        if self.max_repeat > 0 {
            for value in query.split('&').filter_map(|pair| pair.split_once('=')) {
                let (_, value) = value;
                if let Some(token) = most_repeated(value) {
                    if token > self.max_repeat {
                        return Some(format!("`{}` repeated {token}×", token_value(value, token)));
                    }
                }
            }
        }
        None
    }
}

/// Rebuild the query string as the link had it.
///
/// The parsed node keeps unmodelled parameters in `extra`, but the ordering and
/// the `?` are gone, so this is an approximation — good enough for substring and
/// parameter-name checks, which is all the filter does. The library's own
/// annotations are excluded, or every node would look like it carried metadata.
fn query_string(node: &Node) -> String {
    if node.extra.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = node
        .extra
        .iter()
        .filter(|(key, _)| !Node::INTERNAL_KEYS.contains(&key.as_str()))
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    parts.sort();
    parts.join("&")
}

/// The highest repetition count of any single token in a value.
fn most_repeated(value: &str) -> Option<usize> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    let mut best = 0;
    // Split on the separators these padded values use; a handle list and a
    // dashed repeat have different shapes but the same smell.
    for token in value.split([',', ';', '-', '/']) {
        let token = token.trim();
        // Anything long enough to be a name, path or number is real content; a
        // one-letter fragment repeating is not a name.
        if token.len() < 3 {
            continue;
        }
        let count = counts.entry(token).or_insert(0);
        *count += 1;
        best = best.max(*count);
    }
    (best > 1).then_some(best)
}

/// A short, readable form of what repeated, for the log line.
fn token_value(value: &str, times: usize) -> String {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for token in value.split([',', ';', '-', '/']) {
        let token = token.trim();
        if token.len() < 3 {
            continue;
        }
        let count = counts.entry(token).or_insert(0);
        *count += 1;
    }
    counts
        .into_iter()
        .find(|(_, c)| *c == times)
        .map(|(token, _)| token.to_string())
        .unwrap_or_default()
}

/// Remove junk nodes, returning what was dropped and why.
pub fn strip(nodes: Vec<Node>, filter: &JunkFilter) -> (Vec<Node>, Vec<(Node, String)>) {
    let mut kept = Vec::with_capacity(nodes.len());
    let mut dropped = Vec::new();
    for node in nodes {
        match filter.reject(&node) {
            Some(reason) => dropped.push((node, reason)),
            None => kept.push(node),
        }
    }
    (kept, dropped)
}

/// Remove junk nodes, keeping only what survives.
pub fn clean(nodes: Vec<Node>) -> Vec<Node> {
    strip(nodes, &JunkFilter::default()).0
}