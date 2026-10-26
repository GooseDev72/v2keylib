//! Named tiers: whitelist/blacklist groups composed into balancers.
//!
//! The shape this supports:
//!
//! ```text
//! wl1 = 1-5,8
//! wl2 = 11-20
//! wl3 = reality          // a predicate over the list
//! bl1 = 7,9
//!
//! b1 = wl1 + wl2 + wl3
//! b2 = all
//! b3 = all - bl1
//! ```
//!
//! `wl*` and `bl*` are *tiers*: named subsets that can be referenced by name.
//! `b*` is a tier too, but it is also emitted as its own balancer. Nothing is
//! nested in the output — XRay cannot resolve a balancer tag from another
//! balancer's selector — so every emitted tier is flattened to the concrete
//! outbound tags of its members.
//!
//! A tier may only reference tiers declared *above* it, which makes the graph a
//! DAG by construction and turns a forward reference into a clear error.

use std::collections::BTreeMap;

use crate::balancer::plan::{Export, Plan, TagScheme, Warning};
use crate::error::{Error, Result};

/// How a member expression picks nodes.
#[derive(Clone, Debug)]
enum Op {
    All,
    None,
    Numbers(Vec<usize>),
    Name(String),
}

/// How two terms combine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Combine {
    /// `+` or `|`
    Add,
    Sub,
    And,
}

/// One term of an expression: `all`, `none`, `1-5,8`, a tier name, a
/// predicate such as `country:DE`, or a parenthesised sub-expression.
#[derive(Clone, Debug)]
enum Term {
    Ref(Op),
    /// `country:DE` style.
    Classifier(String, Option<String>),
    /// `(wl1 + wl2)` — evaluated with the same rules.
    Group(Box<Expr>),
}

#[derive(Clone, Debug)]
struct Expr {
    /// Left-to-right `+`, `-` and `&` over terms. Same precedence, evaluated in
    /// written order, so `a - b & c` is `(a - b) & c`.
    ops: Vec<(Combine, Term)>,
}

/// A named subset, and optionally a balancer that gets emitted for it.
#[derive(Clone, Debug)]
pub struct Tier {
    pub name: String,
    pub kind: crate::config::BalancerKind,
    /// Member expression, in the syntax described above.
    pub expr: String,
    /// Emit a balancer config for this tier.
    pub emit: bool,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u32>,
    pub comment: Option<String>,
}

impl Tier {
    pub fn new(name: impl Into<String>, expr: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: crate::config::BalancerKind::LeastPing,
            expr: expr.into(),
            emit: true,
            url: None,
            interval: None,
            tolerance: None,
            comment: None,
        }
    }

    /// A building block that is *not* emitted on its own.
    pub fn hidden(name: impl Into<String>, expr: impl Into<String>) -> Self {
        Self {
            emit: false,
            ..Self::new(name, expr)
        }
    }

    pub fn kind(mut self, kind: crate::config::BalancerKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }

    pub fn with_interval(mut self, secs: u64) -> Self {
        self.interval = Some(secs);
        self
    }

    pub fn as_group(mut self) -> Self {
        self.kind = crate::config::BalancerKind::Random;
        self
    }
}

/// Resolves predicates like `country:DE` against a node.
/// Is `value` one of the comma-separated things in `wanted`?
fn listed(value: &str, wanted: &str) -> bool {
    wanted
        .split(',')
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .any(|w| value.eq_ignore_ascii_case(w))
}

pub trait Classifier {
    fn matches(&self, node: &crate::node::Node, predicate: &str, arg: Option<&str>) -> bool;
}

/// Classifiers that are always available.
pub struct BuiltinClassifier;

impl Classifier for BuiltinClassifier {
    fn matches(&self, node: &crate::node::Node, predicate: &str, arg: Option<&str>) -> bool {
        use crate::node::{Security, TransportKind};
        let want = arg.unwrap_or("").to_ascii_lowercase();
        match predicate {
            // A country, or a list of them: `country:RU,BY` reads the way the
            // thing it describes reads, and the list form is what makes "every
            // country where this service is closed" expressible at all.
            "country" => node
                .extra
                .get("country")
                .map(|c| listed(c, &want))
                .unwrap_or(false),
            // Where a node came from, and what kind of channel it was on.
            //
            // `source` and `channel` are stamped at fetch time, so a plan can
            // select by them without matching on node names — which a provider
            // is free to rewrite at any moment, and did.
            "source" => node
                .extra
                .get("source")
                .map(|s| s.eq_ignore_ascii_case(&want))
                .unwrap_or(false),
            // A channel may be a list — `lte,ai` — because one provider can
            // legitimately be both: the same config that walks through a mobile
            // whitelist is often the one that works with an AI service. Matching
            // any of the listed channels keeps the plan selectors written as
            // `channel:lte` and `channel:ai` either way.
            "channel" => node
                .extra
                .get("channel")
                .map(|c| {
                    c.split(',')
                        .map(|part| part.trim())
                        .any(|part| part.eq_ignore_ascii_case(&want))
                })
                .unwrap_or(false),
            // The absence of a thing, as a predicate: `not_country:RU,CN` is not
            // expressible as an operator over the ones that exist.
            "not_country" => !node
                .extra
                .get("country")
                .map(|c| listed(c, &want))
                .unwrap_or(false),
            "protocol" | "proto" => node.protocol.as_str() == want,
            "security" | "sec" => node.security.as_str() == want,
            "type" | "transport" => node.transport.kind.as_str() == want,
            "flow" => node.flow.as_deref().map(str::to_string) == arg.map(str::to_string),
            "reality" => node.security == Security::Reality,
            "tls" => node.security == Security::Tls,
            "xhttp" => node.transport.kind == TransportKind::Xhttp,
            "grpc" => node.transport.kind == TransportKind::Grpc,
            "ws" => node.transport.kind == TransportKind::Ws,
            "tcp" | "raw" => node.transport.kind == TransportKind::Tcp,
            "stub" => crate::filter::stubs::StubFilter::default()
                .is_stub(node)
                .is_some(),
            "hostname" => node.address.parse::<std::net::IpAddr>().is_err(),
            "ip" => node.address.parse::<std::net::IpAddr>().is_ok(),
            "has_sni" => node.sni.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "has_flow" => node.flow.as_deref().map(|f| !f.is_empty()).unwrap_or(false),
            "protocols" => want
                .split(',')
                .any(|p| node.protocol.as_str() == p.trim().to_ascii_lowercase()),
            "label" | "name" | "remark" => node
                .label
                .as_deref()
                .map(|l| l.to_ascii_lowercase().contains(&want))
                .unwrap_or(false),
            // Any of several words, comma separated: `label_any:lte,wl,обход`.
            //
            // A provider names its nodes by what they are for rather than by
            // where they are — `🇩🇪 LTE - Обход глушилок #11`, `● Exclusive`,
            // `Обход`, `WL` — so selecting a purpose means matching a set of
            // words, which a single `label` substring cannot express.
            "label_any" | "name_any" | "remark_any" => {
                let lower = node.label.as_deref().unwrap_or("").to_ascii_lowercase();
                want.split(',')
                    .map(str::trim)
                    .filter(|word| !word.is_empty())
                    .any(|word| lower.contains(word))
            }
            "sni" => node
                .sni
                .as_deref()
                .map(|s| s.to_ascii_lowercase().contains(&want))
                .unwrap_or(false),
            "address" | "addr" => node.address.to_ascii_lowercase().contains(&want),
            // A decision made elsewhere and left on the node.
            //
            // Whether a node can get through a mobile whitelist depends on where
            // it *connects*, not on how it is named or which channel shipped it,
            // and answering that needs a list of addresses that does not belong
            // in a selector expression. So whatever decided it stamps a flag and
            // the plan asks for `flag:<name>`.
            //
            // "0", "false", "no" and the empty string count as not set, so a flag
            // can be written down and then revoked without editing the plan.
            // Which of the site checks a node passed. `checks=gstatic,youtube`
            // on the node, so a plan can ask for the exact thing rather than for
            // "unblocks something" — a YouTube group and a Telegram group are
            // different requests, and only one of them may be answerable from
            // where the node exits.
            "site" => node
                .extra
                .get("checks")
                .map(|c| {
                    c.split(',')
                        .map(|s| s.trim().to_ascii_lowercase())
                        .any(|s| s == want)
                })
                .unwrap_or(false),
            "flag" => match node.extra.get(&want) {
                Some(v) => {
                    !v.is_empty()
                        && !matches!(
                            v.to_ascii_lowercase().as_str(),
                            "0" | "false" | "no" | "off"
                        )
                }
                None => false,
            },
            _ => false,
        }
    }
}

/// An ordered set of tiers.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    pub tiers: Vec<Tier>,
    pub default: Option<String>,
    pub tag_scheme: TagScheme,
    pub classifier_names: Vec<String>,
    /// Carried through to the [`Plan`] this builder turns into.
    pub inbounds: bool,
}

impl Builder {
    pub fn new() -> Self {
        Self {
            tiers: Vec::new(),
            default: None,
            tag_scheme: TagScheme::Index,
            inbounds: false,
            classifier_names: Vec::new(),
        }
    }

    pub fn with_tag_scheme(mut self, scheme: TagScheme) -> Self {
        self.tag_scheme = scheme;
        self
    }

    /// Emit local SOCKS/HTTP inbounds so the config runs standalone.
    pub fn with_inbounds(mut self, yes: bool) -> Self {
        self.inbounds = yes;
        self
    }

    /// Declare a tier. Emission order follows declaration order.
    pub fn define(mut self, tier: Tier) -> Self {
        self.tiers.push(tier);
        self
    }

    /// In-place variant, for building a plan in a loop or from a host language
    /// that hands out `&mut`.
    pub fn push(&mut self, tier: Tier) -> &mut Self {
        self.tiers.push(tier);
        self
    }

    /// In-place variant of [`Builder::set_default`].
    pub fn set_default_mut(&mut self, tag: impl Into<String>) -> &mut Self {
        self.default = Some(tag.into());
        self
    }

    pub fn set_default(mut self, tag: impl Into<String>) -> Self {
        self.default = Some(tag.into());
        self
    }

    /// Resolve every tier to concrete node indices.
    pub fn resolve(&self, nodes: &[crate::node::Node]) -> Result<BTreeMap<String, Vec<usize>>> {
        let mut done: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for tier in &self.tiers {
            let mask = self.eval(&tier.expr, nodes, &done)?;
            let mut members: Vec<usize> = (0..nodes.len()).filter(|&i| mask[i]).collect();
            members.sort_unstable();
            done.insert(tier.name.clone(), members);
        }
        Ok(done)
    }

    fn eval(
        &self,
        expr: &str,
        nodes: &[crate::node::Node],
        done: &BTreeMap<String, Vec<usize>>,
    ) -> Result<Vec<bool>> {
        let parsed = parse_expr(expr, nodes.len())?;
        self.eval_parsed(&parsed, nodes, done)
    }

    fn eval_parsed(
        &self,
        parsed: &Expr,
        nodes: &[crate::node::Node],
        done: &BTreeMap<String, Vec<usize>>,
    ) -> Result<Vec<bool>> {
        let mut mask = vec![false; nodes.len()];
        for (combine, term) in &parsed.ops {
            let term_mask = self.eval_term(term, nodes, done)?;
            for (i, slot) in mask.iter_mut().enumerate() {
                *slot = match combine {
                    Combine::Add => *slot || term_mask[i],
                    Combine::Sub => *slot && !term_mask[i],
                    Combine::And => *slot && term_mask[i],
                };
            }
        }
        Ok(mask)
    }

    fn eval_term(
        &self,
        term: &Term,
        nodes: &[crate::node::Node],
        done: &BTreeMap<String, Vec<usize>>,
    ) -> Result<Vec<bool>> {
        let mut mask = vec![false; nodes.len()];
        let result = match term {
            Term::Ref(Op::All) => vec![true; nodes.len()],
            Term::Ref(Op::None) => mask,
            Term::Ref(Op::Numbers(indices)) => {
                for &i in indices {
                    mask[i] = true;
                }
                mask
            }
            Term::Ref(Op::Name(name)) => {
                let members = done.get(name).ok_or_else(|| {
                    Error::Balancer(format!("unknown tier `{name}`; declare it before use"))
                })?;
                for &i in members {
                    mask[i] = true;
                }
                mask
            }
            Term::Group(sub) => return self.eval_parsed(sub, nodes, done),
            Term::Classifier(predicate, arg) => {
                let classifier = BuiltinClassifier;
                for (i, node) in nodes.iter().enumerate() {
                    mask[i] = classifier.matches(node, predicate, arg.as_deref());
                }
                if !mask.iter().any(|m| *m) {
                    let label = match arg {
                        Some(a) => format!("{predicate}:{a}"),
                        None => predicate.clone(),
                    };
                    tracing::warn!("predicate `{label}` matched nothing");
                }
                mask
            }
        };
        Ok(result)
    }

    /// Validate and export.
    pub fn export(&self, nodes: &[crate::node::Node], original: &[Value]) -> Result<Export> {
        self.plan(nodes)?.export(nodes, original)
    }

    /// All balancers in one config, in declaration order.
    pub fn export_single(
        &self,
        nodes: &[crate::node::Node],
        original: &[Value],
    ) -> Result<crate::balancer::plan::SingleExport> {
        let plan = self.plan(nodes)?;
        plan.export_single(nodes, original)
    }

    /// The flattened [`Plan`] this builder describes.
    pub fn plan(&self, nodes: &[crate::node::Node]) -> Result<Plan> {
        let resolved = self.resolve(nodes)?;
        for tier in &self.tiers {
            if tier.emit && resolved[&tier.name].is_empty() {
                return Err(Error::Balancer(format!(
                    "tier `{}` resolved to no members; XRay needs a non-empty selector",
                    tier.name
                )));
            }
        }
        Ok(Plan {
            inbounds: self.inbounds,
            groups: self
                .tiers
                .iter()
                .filter(|t| t.emit)
                .map(|t| crate::balancer::plan::Group {
                    name: t.name.clone(),
                    kind: t.kind,
                    members: resolved[&t.name].clone(),
                    url: t.url.clone(),
                    interval: t.interval,
                    tolerance: t.tolerance,
                    comment: t.comment.clone(),
                })
                .collect(),
            default: self.default.clone(),
            tag_scheme: self.tag_scheme,
        })
    }

    /// Dry run: what each tier resolves to, for a human-readable summary.
    pub fn summary(&self, nodes: &[crate::node::Node]) -> Result<Vec<(String, String, usize)>> {
        let resolved = self.resolve(nodes)?;
        Ok(self
            .tiers
            .iter()
            .map(|t| (t.name.clone(), t.expr.clone(), resolved[&t.name].len()))
            .collect())
    }
}

use serde_json::Value;

/// Split a member expression on its operators.
///
/// `-` is ambiguous: it separates a range (`1-5`) and subtracts (`all - bl1`).
/// The rule that keeps both readable is that a binary `-` must be surrounded by
/// whitespace, while `+` is unambiguous and always an operator. So `1-2` is the
/// range 1..2, `all - bl1` is a subtraction, and the typo `all-bl1` produces a
/// clear error instead of silently meaning something else.
fn parse_expr(expr: &str, len: usize) -> Result<Expr> {
    let expr = expr.split('#').next().unwrap_or("").trim();
    if expr.is_empty() {
        return Err(Error::Balancer("empty member expression".into()));
    }
    let bytes = expr.as_bytes();
    let mut ops = Vec::new();
    let mut term_start = 0usize;
    let mut combine = Combine::Add;
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i] as char;
        let is_op = match c {
            '+' | '&' | '|' => true,
            '-' => {
                // ambiguous with a range, so require whitespace on both sides
                i > 0
                    && expr[..i].ends_with(char::is_whitespace)
                    && bytes
                        .get(i + 1)
                        .map(|b| (*b as char).is_whitespace())
                        .unwrap_or(false)
            }
            _ => false,
        };
        // skip over parenthesised sub-expressions, so their operators are not
        // mistaken for top-level ones
        if c == '(' {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] as char {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if !is_op {
            i += 1;
            continue;
        }
        let piece = expr[term_start..i].trim();
        if !piece.is_empty() {
            ops.push((combine, parse_term(piece, len)?));
        }
        combine = match c {
            '+' | '|' => Combine::Add,
            '&' => Combine::And,
            _ => Combine::Sub,
        };
        i += 1;
        while i < bytes.len() && (bytes[i] as char).is_whitespace() {
            i += 1;
        }
        term_start = i;
    }
    let tail = expr[term_start..].trim();
    if !tail.is_empty() {
        ops.push((combine, parse_term(tail, len)?));
    }
    if ops.is_empty() {
        return Err(Error::Balancer(format!("cannot parse expression {expr:?}")));
    }
    Ok(Expr { ops })
}

fn parse_term(piece: &str, len: usize) -> Result<Term> {
    let piece = piece.trim();
    if piece.is_empty() {
        return Err(Error::Balancer("empty term".into()));
    }

    // parenthesised sub-expression, e.g. (wl1 + wl2)
    if piece.starts_with('(') {
        if !piece.ends_with(')') {
            return Err(Error::Balancer(format!(
                "unbalanced parentheses in {piece:?}"
            )));
        }
        let inner = &piece[1..piece.len() - 1];
        let sub = parse_expr(inner, len)?;
        return Ok(Term::Group(Box::new(sub)));
    }

    let lower = piece.to_ascii_lowercase();
    match lower.as_str() {
        "all" | "*" | ":" => return Ok(Term::Ref(Op::All)),
        "none" | "-" | "empty" => return Ok(Term::Ref(Op::None)),
        _ => {}
    }

    // number selection
    if piece
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, ',' | '-' | ' ' | ';' | '#'))
    {
        let indices = crate::select::parse_selection(piece, len)?;
        return Ok(Term::Ref(Op::Numbers(indices)));
    }

    // predicate: known keyword optionally with :argument
    const PREDICATES: &[&str] = &[
        "country",
        "protocol",
        "proto",
        "security",
        "sec",
        "type",
        "transport",
        "flow",
        "source",
        "channel",
        "not_country",
        "flag",
        "site",
        "reality",
        "tls",
        "xhttp",
        "grpc",
        "ws",
        "tcp",
        "raw",
        "stub",
        "hostname",
        "ip",
        "has_sni",
        "has_flow",
        "protocols",
        "label",
        "name",
        "remark",
        "sni",
        "address",
        "addr",
        // Comma-separated lists. A comma is safe inside an argument: the split
        // that produces number lists runs before this point, and none of these
        // predicates take a bare number.
        "label_any",
        "name_any",
        "remark_any",
    ];
    if let Some((head, arg)) = piece.split_once(':') {
        if PREDICATES.contains(&head.to_ascii_lowercase().as_str()) {
            let arg = arg.trim();
            // An argument containing an operator or a space means the expression
            // was mis-parsed; matching nothing silently would be worse.
            if arg.is_empty()
                || arg
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '+' | '-' | '&' | '|'))
            {
                return Err(Error::Balancer(format!(
                    "predicate `{piece}` needs a single-value argument, e.g. `{head}:FI`"
                )));
            }
            return Ok(Term::Classifier(
                head.to_ascii_lowercase(),
                Some(arg.to_string()),
            ));
        }
    }
    if PREDICATES.contains(&lower.as_str()) {
        return Ok(Term::Classifier(lower, None));
    }

    // a tier name is never allowed to contain `-` together with other words:
    // that is almost always a forgotten subtraction
    if piece.contains('-')
        && !piece
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == ' ')
    {
        return Err(Error::Balancer(format!(
            "cannot parse term {piece:?}; separate subtraction with spaces: `all - bl1`"
        )));
    }

    // otherwise a tier name; an unknown bare word is almost always a typo, so
    // say so instead of guessing
    if !piece
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(Error::Balancer(format!("cannot parse term {piece:?}")));
    }
    Ok(Term::Ref(Op::Name(piece.to_string())))
}

/// Warnings collected while resolving, kept for the summary.
pub fn describe(builder: &Builder) -> Vec<Warning> {
    builder
        .tiers
        .iter()
        .filter(|t| !t.emit)
        .map(|t| {
            Warning(format!(
                "tier `{}` is a building block and is not emitted",
                t.name
            ))
        })
        .collect()
}
