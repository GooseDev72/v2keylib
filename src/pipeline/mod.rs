//! The end-to-end pipeline.
//!
//! ```no_run
//! use v2keylib::config::{BalancerKind, BalancerSpec};
//! use v2keylib::pipeline::{Input, Output, Pipeline};
//!
//! # async fn run() -> v2keylib::error::Result<()> {
//! let outputs = Pipeline::new()
//!     .input(Input::Url("https://example.com/sub".into()))
//!     .dedup(true)
//!     .probe(v2keylib::probe::ProbeKind::Tcp)
//!     .output(Output::Links)
//!     .output(Output::XrayJson(Some(BalancerSpec::new("auto", BalancerKind::UrlTest))))
//!     .run()
//!     .await?;
//! println!("{} outputs", outputs.len());
//! # Ok(()) }
//! ```

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{self, BalancerKind, BalancerSpec, Format};
use crate::error::Result;
use crate::filter::{self, ip::IpMatcher, ip::Whitelist};
use crate::geo::{self, GeoResolver};
use crate::links;
use crate::node::{Node, Protocol};
use crate::probe::{self, ProbeKind, ProbeOptions, ProbeResult};
use crate::subscription::{self, FetchOptions};

/// Where the keys come from.
#[derive(Clone, Debug)]
pub enum Input {
    Url(String),
    Text(String),
    Nodes(Vec<Node>),
}

/// How the result should be rendered.
#[derive(Clone, Debug)]
pub enum Output {
    /// Plain `vless://`-style links.
    Links,
    XrayJson(Option<BalancerSpec>),
    SingBoxJson(Option<BalancerSpec>),
    MihomoYaml(Option<BalancerSpec>),
}

impl Output {
    pub fn format(&self) -> Option<Format> {
        match self {
            Output::Links => None,
            Output::XrayJson(_) => Some(Format::XrayJson),
            Output::SingBoxJson(_) => Some(Format::SingBoxJson),
            Output::MihomoYaml(_) => Some(Format::MihomoYaml),
        }
    }

    pub fn spec(&self) -> Option<&BalancerSpec> {
        match self {
            Output::Links => None,
            Output::XrayJson(s) | Output::SingBoxJson(s) | Output::MihomoYaml(s) => s.as_ref(),
        }
    }

    /// Bare config with no balancer.
    pub fn plain(format: Format) -> Self {
        match format {
            Format::XrayJson => Output::XrayJson(None),
            Format::SingBoxJson => Output::SingBoxJson(None),
            Format::MihomoYaml => Output::MihomoYaml(None),
        }
    }

    /// Config with a balancer over all nodes.
    pub fn balanced(format: Format, name: &str, kind: BalancerKind) -> Self {
        let spec = BalancerSpec::new(name, kind);
        match format {
            Format::XrayJson => Output::XrayJson(Some(spec)),
            Format::SingBoxJson => Output::SingBoxJson(Some(spec)),
            Format::MihomoYaml => Output::MihomoYaml(Some(spec)),
        }
    }
}

/// A composable key-processing pipeline.
pub struct Pipeline {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    dedup: bool,
    dedup_by_endpoint: bool,
    whitelist: Option<Whitelist>,
    blacklist: Vec<IpMatcher>,
    allow_private: bool,
    countries: Vec<String>,
    excluded_countries: Vec<String>,
    protocols: Vec<Protocol>,
    ports: Option<Vec<u16>>,
    name_needles: Vec<String>,
    probe: Option<(ProbeKind, ProbeOptions)>,
    /// Local resolver used to stamp `extra["country"]` onto every node.
    /// See [`Pipeline::geo_marks`].
    geo_resolver: Option<Arc<dyn GeoResolver + Send + Sync>>,
    limit: Option<usize>,
    fetch_options: FetchOptions,
    /// Keep only nodes whose address is already an IP literal.
    only_ip_literals: bool,
    /// Drop nodes with a hostname address (needs no DNS).
    only_hostnames: bool,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            dedup: true,
            dedup_by_endpoint: false,
            whitelist: None,
            blacklist: Vec::new(),
            allow_private: false,
            countries: Vec::new(),
            excluded_countries: Vec::new(),
            protocols: Vec::new(),
            ports: None,
            name_needles: Vec::new(),
            probe: None,
            geo_resolver: None,
            limit: None,
            fetch_options: FetchOptions::default(),
            only_ip_literals: false,
            only_hostnames: false,
        }
    }
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn urls(mut self, urls: impl IntoIterator<Item = String>) -> Self {
        for url in urls {
            self.inputs.push(Input::Url(url));
        }
        self
    }

    pub fn output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn dedup(mut self, on: bool) -> Self {
        self.dedup = on;
        self
    }

    pub fn dedup_by_endpoint(mut self, on: bool) -> Self {
        self.dedup_by_endpoint = on;
        self
    }

    pub fn whitelist(mut self, wl: Whitelist) -> Self {
        self.whitelist = Some(wl);
        self
    }

    pub fn whitelist_cidrs(mut self, cidrs: &str) -> Result<Self> {
        self.whitelist = Some(Whitelist::parse_list(cidrs)?);
        Ok(self)
    }

    pub fn blacklist_cidrs(mut self, cidrs: &str) -> Result<Self> {
        for token in cidrs.split([' ', ',', '\n', '\t']) {
            let token = token.trim();
            if token.is_empty() || token.starts_with('#') {
                continue;
            }
            self.blacklist.push(IpMatcher::parse(token)?);
        }
        Ok(self)
    }

    pub fn allow_private(mut self, on: bool) -> Self {
        self.allow_private = on;
        self
    }

    /// Keep only nodes whose stamped country is in this list.
    ///
    /// Requires country marks: call [`Pipeline::geo_marks`] (IP-literal nodes)
    /// or [`crate::geo::annotate_api`] (hostnames) first.
    pub fn filter_by_country(mut self, countries: &[String]) -> Self {
        self.countries = countries.to_vec();
        self
    }

    /// Drop nodes whose stamped country is in this list.
    pub fn exclude_country(mut self, countries: &[String]) -> Self {
        self.excluded_countries = countries.to_vec();
        self
    }

    pub fn protocols(mut self, protocols: &[Protocol]) -> Self {
        self.protocols = protocols.to_vec();
        self
    }

    pub fn ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = Some(ports);
        self
    }

    pub fn name_contains(mut self, needles: &[String]) -> Self {
        self.name_needles = needles.to_vec();
        self
    }

    pub fn only_ip_literals(mut self, on: bool) -> Self {
        self.only_ip_literals = on;
        self
    }

    pub fn only_hostnames(mut self, on: bool) -> Self {
        self.only_hostnames = on;
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn probe(mut self, kind: ProbeKind) -> Self {
        self.probe = Some((kind, ProbeOptions::default()));
        self
    }

    pub fn probe_with(mut self, kind: ProbeKind, opts: ProbeOptions) -> Self {
        self.probe = Some((kind, opts));
        self
    }

    pub fn fetch_options(mut self, opts: FetchOptions) -> Self {
        self.fetch_options = opts;
        self
    }

    /// Stamp `extra["country"]` onto every node using `resolver` (an MMDB, an
    /// ip/country table, ...).
    ///
    /// Only IP-literal addresses can be resolved here; for hostnames use
    /// [`crate::geo::annotate_api`] with a remote IP-API first.
    pub fn geo_marks<R: GeoResolver + 'static>(self, resolver: R) -> Self {
        self.geo_marks_shared(Arc::new(resolver))
    }

    /// Same, for a resolver shared with other parts of the program.
    pub fn geo_marks_shared(self, resolver: Arc<dyn GeoResolver + Send + Sync>) -> Self {
        Self {
            geo_resolver: Some(resolver),
            ..self
        }
    }

    /// Run the pipeline and return one rendered string per configured output.
    pub async fn run(self) -> Result<Vec<String>> {
        let outputs = self.outputs.clone();
        let nodes = self.filtered_nodes().await?;
        if outputs.is_empty() {
            return Ok(vec![links::render_all(&nodes)?]);
        }
        outputs.iter().map(|o| render_output(o, &nodes)).collect()
    }

    /// Same as [`Pipeline::run`] but returns the surviving nodes, so the caller
    /// can render extra formats or inspect them.
    pub async fn run_with_nodes(self) -> Result<Vec<Node>> {
        self.filtered_nodes().await
    }

    async fn filtered_nodes(self) -> Result<Vec<Node>> {
        let mut nodes = self.collect_nodes().await?;
        nodes = self.apply_filters(nodes);
        if let Some((kind, opts)) = self.probe.clone() {
            nodes = filter_by_probe(nodes, kind, &opts).await;
        }
        if let Some(limit) = self.limit {
            nodes.truncate(limit);
        }
        Ok(nodes)
    }

    async fn collect_nodes(&self) -> Result<Vec<Node>> {
        let mut nodes: Vec<Node> = Vec::new();
        for input in &self.inputs {
            match input {
                Input::Nodes(n) => nodes.extend(n.clone()),
                Input::Text(text) => nodes.extend(subscription::parse_body(text)?.nodes()),
                Input::Url(url) => {
                    let sub = subscription::fetch(url, &self.fetch_options).await?;
                    nodes.extend(sub.nodes());
                }
            }
        }
        if self.dedup {
            nodes = filter::dedup(nodes);
        }
        if self.dedup_by_endpoint {
            nodes = filter::dedup_by_endpoint(nodes);
        }
        Ok(nodes)
    }

    fn apply_filters(&self, nodes: Vec<Node>) -> Vec<Node> {
        let mut nodes = nodes;

        if self.only_ip_literals {
            nodes.retain(|n| n.address.parse::<IpAddr>().is_ok());
        }
        if self.only_hostnames {
            nodes.retain(|n| n.address.parse::<IpAddr>().is_err());
        }
        if !self.protocols.is_empty() {
            nodes = filter::keep_protocols(nodes, &self.protocols);
        }
        if let Some(ports) = &self.ports {
            nodes = filter::keep_ports(nodes, ports);
        }
        if !self.name_needles.is_empty() {
            nodes = filter::keep_by_name(nodes, &self.name_needles);
        }
        if let Some(wl) = &self.whitelist {
            let mut wl = wl.clone();
            wl.allow_private |= self.allow_private;
            if let Ok(filtered) = wl.filter(nodes.clone()) {
                nodes = filtered;
            }
        }
        if !self.blacklist.is_empty() {
            nodes = filter::drop_ips(nodes, &self.blacklist);
        }
        if let Some(resolver) = &self.geo_resolver {
            geo::annotate(&mut nodes, resolver.as_ref(), None);
        }
        if !self.countries.is_empty() {
            nodes = geo::filter_by_country(nodes, &self.countries);
        }
        if !self.excluded_countries.is_empty() {
            let excluded: BTreeSet<String> = self
                .excluded_countries
                .iter()
                .map(|c| c.to_ascii_uppercase())
                .collect();
            nodes.retain(|n| {
                !n.extra
                    .get("country")
                    .map(|c| excluded.contains(&c.to_ascii_uppercase()))
                    .unwrap_or(false)
            });
        }
        nodes
    }
}

fn render_output(output: &Output, nodes: &[Node]) -> Result<String> {
    match output {
        Output::Links => links::render_all(nodes),
        other => match other.spec() {
            Some(spec) => config::render(other.format().unwrap(), nodes, Some(spec)),
            None => {
                if nodes.len() == 1 {
                    config::render_auto(nodes, None)
                } else {
                    config::render(other.format().unwrap(), nodes, None)
                }
            }
        },
    }
}



pub type PipelineResult = Result<String>;

/// Probe every node concurrently and drop the dead ones.
pub async fn filter_by_probe(
    nodes: Vec<Node>,
    kind: ProbeKind,
    opts: &ProbeOptions,
) -> Vec<Node> {
    let results = probe_all(nodes.clone(), kind, opts).await;
    let keep: Vec<bool> = results.iter().map(|r| r.alive).collect();
    nodes
        .into_iter()
        .zip(keep)
        .filter(|(_, alive)| *alive)
        .map(|(n, _)| n)
        .collect()
}

/// Probe every node, returning one result per node in input order.
pub async fn probe_all(nodes: Vec<Node>, kind: ProbeKind, opts: &ProbeOptions) -> Vec<ProbeResult> {
    use futures::StreamExt;
    let concurrency = opts.concurrency.max(1);
    let mut results: Vec<ProbeResult> = futures::stream::iter(nodes.into_iter().enumerate().map(
        |(index, node)| {
            let opts = opts.clone();
            async move {
                let start = std::time::Instant::now();
                let outcome = probe::probe_node(&node, kind, &opts).await;
                ProbeResult {
                    index,
                    alive: outcome.is_ok(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    error: outcome.err().map(|e| e.to_string()),
                }
            }
        },
    ))
    .buffer_unordered(concurrency)
    .collect()
    .await;
    results.sort_by_key(|r| r.index);
    results
}

/// Probe and stop as soon as `limit` live nodes are found — the fast path for
/// "give me 10 working keys" requests.
pub async fn first_alive(
    nodes: Vec<Node>,
    kind: ProbeKind,
    opts: &ProbeOptions,
    limit: usize,
) -> Vec<Node> {
    use futures::stream::StreamExt;
    let concurrency = opts.concurrency.max(1);
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut stream = futures::stream::iter(nodes.into_iter().map(|node| {
        let semaphore = semaphore.clone();
        let opts = opts.clone();
        async move {
            let _permit = semaphore.acquire_owned().await.ok()?;
            let alive = probe::probe_node(&node, kind, &opts).await.is_ok();
            Some((node, alive))
        }
    }))
    .buffer_unordered(concurrency);

    let mut alive: Vec<Node> = Vec::new();
    while let Some(item) = stream.next().await {
        if let Some((node, true)) = item {
            alive.push(node);
            if alive.len() >= limit {
                break;
            }
        }
    }
    alive
}
