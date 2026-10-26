//! Python bindings (PyO3).
//!
//! The Rust API is async in places (`fetch`, `cascade` with a remote source);
//! Python is synchronous, so those calls block on an internal runtime and
//! release the GIL while waiting, so they do not freeze the interpreter.
//!
//! Everything that can fail raises a Python exception (`v2keylib.V2Error`) with
//! the Rust error text, rather than returning `None` and hiding the reason.

use std::collections::BTreeMap;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::balancer::flatten;
use crate::balancer::tiers::{Builder, Tier};
use crate::config::{self, BalancerKind, Format};
use crate::filter::stubs::StubFilter;
use crate::geo::{Cascade, GeoDb};
use crate::node::{Node, Protocol, Security, TransportKind};
use crate::probe::{ProbeKind, ProbeOptions};
use crate::{links, pipeline, subscription};

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

/// A blocking runtime for the async parts of the library.
fn runtime() -> PyResult<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(err)
}

// ---------------------------------------------------------------- Node

/// A proxy node.
///
/// ``protocol``, ``security`` and ``transport`` are plain strings so they can be
/// compared in Python without importing Rust enums.
#[pyclass(module = "v2keylib", name = "Node")]
#[derive(Clone)]
pub struct PyNode {
    pub inner: Node,
}

impl From<Node> for PyNode {
    fn from(inner: Node) -> Self {
        PyNode { inner }
    }
}

fn opt_str(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

#[pymethods]
impl PyNode {
    #[new]
    #[pyo3(signature = (protocol, address, port, **kw))]
    #[allow(clippy::too_many_arguments)]
    fn new(protocol: &str, address: &str, port: u16, kw: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let protocol = match protocol.to_ascii_lowercase().as_str() {
            "vless" => Protocol::Vless,
            "vmess" => Protocol::Vmess,
            "trojan" => Protocol::Trojan,
            "hysteria" => Protocol::Hysteria,
            "hysteria2" | "hy2" => Protocol::Hysteria2,
            "ss" | "shadowsocks" => Protocol::Shadowsocks,
            "tuic" => Protocol::Tuic,
            "socks" | "socks5" => Protocol::Socks,
            "http" => Protocol::Http,
            "anytls" => Protocol::Anytls,
            "wireguard" => Protocol::Wireguard,
            other => {
                return Err(PyValueError::new_err(format!("unknown protocol {other}")));
            }
        };
        let mut node = Node::new(protocol, address, port);
        if let Some(kw) = kw {
            for (key, value) in kw.iter() {
                let key: String = key.extract()?;
                match key.as_str() {
                    "uuid" => node.uuid = value.extract().ok(),
                    "password" => node.password = value.extract().ok(),
                    "method" => node.method = value.extract().ok(),
                    "sni" => node.sni = value.extract().ok(),
                    "security" => {
                        if let Ok(sec) = value.extract::<String>() {
                            node.security = Security::parse(&sec);
                        }
                    }
                    "transport" | "type" => {
                        if let Ok(t) = value.extract::<String>() {
                            node.transport.kind = TransportKind::parse(&t);
                        }
                    }
                    "path" => node.transport.path = value.extract().ok(),
                    "host" => node.transport.host = value.extract().ok(),
                    "mode" => node.transport.mode = value.extract().ok(),
                    "service_name" => node.transport.service_name = value.extract().ok(),
                    "flow" => node.flow = value.extract().ok(),
                    "fp" | "fingerprint" => node.fingerprint = value.extract().ok(),
                    "pbk" | "public_key" => node.public_key = value.extract().ok(),
                    "sid" | "short_id" => node.short_id = value.extract().ok(),
                    "spx" | "spider_x" => node.spider_x = value.extract().ok(),
                    "alpn" => {
                        if let Ok(list) = value.extract::<Vec<String>>() {
                            node.alpn = list;
                        }
                    }
                    "allow_insecure" => node.allow_insecure = value.extract().unwrap_or(false),
                    "label" => node.label = value.extract().ok(),
                    "obfs" => node.obfs = value.extract().ok(),
                    "port_hopping" => node.port_hopping = value.extract().ok(),
                    _ => {}
                }
            }
        }
        Ok(PyNode { inner: node })
    }

    #[getter]
    fn protocol(&self) -> &'static str {
        self.inner.protocol.as_str()
    }

    #[getter]
    fn address(&self) -> &str {
        &self.inner.address
    }

    #[getter]
    fn port(&self) -> u16 {
        self.inner.port
    }

    #[getter]
    fn uuid(&self) -> Option<&str> {
        opt_str(&self.inner.uuid)
    }

    #[getter]
    fn password(&self) -> Option<&str> {
        opt_str(&self.inner.password)
    }

    #[getter]
    fn method(&self) -> Option<&str> {
        opt_str(&self.inner.method)
    }

    #[getter]
    fn security(&self) -> &'static str {
        self.inner.security.as_str()
    }

    #[getter]
    fn sni(&self) -> Option<&str> {
        opt_str(&self.inner.sni)
    }

    #[getter]
    fn alpn(&self) -> Vec<String> {
        self.inner.alpn.clone()
    }

    #[getter]
    fn fingerprint(&self) -> Option<&str> {
        opt_str(&self.inner.fingerprint)
    }

    #[getter]
    fn public_key(&self) -> Option<&str> {
        opt_str(&self.inner.public_key)
    }

    #[getter]
    fn short_id(&self) -> Option<&str> {
        opt_str(&self.inner.short_id)
    }

    #[getter]
    fn flow(&self) -> Option<&str> {
        opt_str(&self.inner.flow)
    }

    #[getter]
    fn transport(&self) -> String {
        self.inner.transport.kind.as_str().to_string()
    }

    #[getter]
    fn path(&self) -> Option<&str> {
        opt_str(&self.inner.transport.path)
    }

    #[getter]
    fn host(&self) -> Option<&str> {
        opt_str(&self.inner.transport.host)
    }

    #[getter]
    fn service_name(&self) -> Option<&str> {
        opt_str(&self.inner.transport.service_name)
    }

    #[getter]
    fn label(&self) -> Option<&str> {
        opt_str(&self.inner.label)
    }

    /// Countries named by the node's own label, in order (`["RU", "PL"]`).
    #[getter]
    fn claimed_route(&self) -> Vec<String> {
        self.inner.claimed_route()
    }

    /// The country the label claims the connection leaves from.
    #[getter]
    fn claimed_exit(&self) -> Option<String> {
        self.inner.claimed_exit()
    }

    #[getter]
    fn country(&self) -> Option<String> {
        opt_str(&self.inner.extra.get("country").cloned()).map(str::to_string)
    }

    #[getter]
    fn ip(&self) -> Option<String> {
        opt_str(&self.inner.extra.get("ip").cloned()).map(str::to_string)
    }

    #[setter]
    fn set_uuid(&mut self, value: Option<String>) {
        self.inner.uuid = value.filter(|v| !v.is_empty());
    }

    #[setter]
    fn set_password(&mut self, value: Option<String>) {
        self.inner.password = value.filter(|v| !v.is_empty());
    }

    #[setter]
    fn set_sni(&mut self, value: Option<String>) {
        self.inner.sni = value.filter(|v| !v.is_empty());
    }

    #[setter]
    fn set_address(&mut self, value: String) {
        self.inner.address = value;
    }

    #[setter]
    fn set_port(&mut self, value: u16) {
        self.inner.port = value;
    }

    #[setter]
    fn set_security(&mut self, value: String) {
        self.inner.security = Security::parse(&value);
    }

    #[setter]
    fn set_transport(&mut self, value: String) {
        self.inner.transport.kind = TransportKind::parse(&value);
    }

    #[setter]
    fn set_path(&mut self, value: Option<String>) {
        self.inner.transport.path = value.filter(|v| !v.is_empty());
    }

    #[setter]
    fn set_host(&mut self, value: Option<String>) {
        self.inner.transport.host = value.filter(|v| !v.is_empty());
    }

    #[setter]
    fn set_country(&mut self, value: Option<String>) {
        self.inner.extra.insert("country".into(), value.unwrap_or_default());
    }

    #[setter]
    fn set_label(&mut self, value: Option<String>) {
        self.inner.label = value;
    }

    #[setter]
    fn set_flow(&mut self, value: Option<String>) {
        self.inner.flow = value;
    }

    /// `address:port`, IPv6 in brackets.
    #[getter]
    fn endpoint(&self) -> String {
        self.inner.socket_addr()
    }

    fn dedup_key(&self) -> String {
        self.inner.dedup_key()
    }

    /// Every parameter that makes this node this node; see `dedup(mode="strict")`.
    fn strict_key(&self) -> String {
        self.inner.strict_key()
    }

    fn is_stub(&self) -> bool {
        StubFilter::default().is_stub(&self.inner).is_some()
    }

    /// Render back into a share link.
    fn to_link(&self) -> PyResult<String> {
        links::render(&self.inner).map_err(err)
    }

    fn __repr__(&self) -> String {
        format!(
            "Node({} {}:{}{}{})",
            self.inner.protocol.as_str(),
            self.inner.address,
            self.inner.port,
            self.inner
                .sni
                .as_deref()
                .map(|s| format!(" sni={s}"))
                .unwrap_or_default(),
            self.inner
                .label
                .as_deref()
                .map(|l| format!(" {l:?}"))
                .unwrap_or_default(),
        )
    }

    fn __str__(&self) -> String {
        links::render(&self.inner).unwrap_or_default()
    }
}

fn to_nodes(list: Vec<PyNode>) -> Vec<Node> {
    list.into_iter().map(|n| n.inner).collect()
}

fn from_nodes(nodes: Vec<Node>) -> Vec<PyNode> {
    nodes.into_iter().map(PyNode::from).collect()
}

// ---------------------------------------------------------------- links

/// Parse a single `vless://`-style link.
#[pyfunction]
fn parse_link(link: &str) -> PyResult<PyNode> {
    links::parse(link).map(PyNode::from).map_err(err)
}

/// Parse a newline-separated list of links, skipping comments and junk.
#[pyfunction]
fn parse_links(text: &str) -> PyResult<Vec<PyNode>> {
    links::parse_list(text)
        .map(from_nodes)
        .map_err(err)
}

/// Render nodes as links, one per line.
#[pyfunction]
fn to_links(nodes: Vec<PyNode>) -> PyResult<String> {
    links::render_all(&to_nodes(nodes)).map_err(err)
}

// ---------------------------------------------------------------- configs

/// Which client a config is for: ``"xray"``, ``"sing-box"`` or ``"mihomo"``.
#[pyfunction]
fn detect_format(text: &str) -> PyResult<String> {
    config::detect(text)
        .map(|f| match f {
            Format::XrayJson => "xray".to_string(),
            Format::SingBoxJson => "sing-box".to_string(),
            Format::MihomoYaml => "mihomo".to_string(),
        })
        .map_err(err)
}

fn format_from(name: &str) -> PyResult<Format> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "xray" | "xray-json" | "xray_json" => Format::XrayJson,
        "sing-box" | "singbox" | "sing_box" => Format::SingBoxJson,
        "mihomo" | "clash" | "yaml" => Format::MihomoYaml,
        other => return Err(PyValueError::new_err(format!("unknown format {other}"))),
    })
}

/// Parse any config (XRay / sing-box / mihomo, incl. a JSON array of configs).
#[pyfunction]
fn parse_config(text: &str) -> PyResult<Vec<PyNode>> {
    config::parse(text).map(|b| from_nodes(b.nodes)).map_err(err)
}

/// Render nodes into a client config.
#[pyfunction]
#[pyo3(signature = (nodes, format = "xray", balancer = None))]
fn to_config(nodes: Vec<PyNode>, format: &str, balancer: Option<String>) -> PyResult<String> {
    let spec = balancer.map(|name| {
        config::BalancerSpec::new(name, BalancerKind::UrlTest).with_url("https://cp.cloudflare.com/generate_204")
    });
    config::render(format_from(format)?, &to_nodes(nodes), spec.as_ref()).map_err(err)
}

/// All balancer/proxy-groups found in a config, as ``{name: [tags...]}``.
#[pyfunction]
fn config_groups(text: &str) -> PyResult<BTreeMap<String, Vec<String>>> {
    let bundle = config::parse(text).map_err(err)?;
    Ok(bundle
        .groups
        .iter()
        .map(|g| (g.name.clone(), g.members.clone()))
        .collect())
}

// ---------------------------------------------------------------- balancers

/// Flatten a config: every group and balancer becomes standalone pieces.
///
/// ``format`` is ``"links"`` for one importable link per node, or a client
/// format (``"xray"``, ``"sing-box"``, ``"mihomo"``) for one standalone config
/// per node. Returns ``[(name, body), ...]``, named `<group>-<n>` so pieces from
/// different groups stay apart.
#[pyfunction]
#[pyo3(signature = (text, format = "links"))]
fn flatten_config(text: &str, format: &str) -> PyResult<Vec<(String, String)>> {
    let bundle = config::parse(text).map_err(err)?;
    if format.eq_ignore_ascii_case("links") {
        let names: Vec<String> = flatten::flatten(&bundle)
            .into_iter()
            .map(|f| f.tag)
            .collect();
        let links = flatten::to_links(&bundle).map_err(err)?;
        return Ok(links
            .lines()
            .zip(names)
            .map(|(link, name)| (name, link.to_string()))
            .collect());
    }

    let configs = flatten::to_configs(&bundle, format_from(format)?).map_err(err)?;
    Ok(configs
        .into_iter()
        .map(|c| (c.flat.tag, c.config))
        .collect())
}

/// An ordered set of balancers, mirroring `balancer::tiers::Builder`.
///
/// ``add_group`` declares a building block that is not emitted;
/// ``add_balancer`` declares one that becomes a config.
#[pyclass(module = "v2keylib", name = "Plan")]
pub struct PyPlan {
    builder: Builder,
    #[pyo3(get)]
    default: Option<String>,
}

#[pymethods]
impl PyPlan {
    #[new]
    fn new() -> Self {
        PyPlan {
            builder: Builder::new(),
            default: None,
        }
    }

    /// Declare a named subset. `expr` is a selection (`1-5,8`), a tier name,
    /// `all`, or a predicate (`country:DE`, `reality`, `grpc`, ...).
    #[pyo3(signature = (name, expr, emit = false))]
    fn add_group(&mut self, name: &str, expr: &str, emit: bool) -> PyResult<()> {
        let tier = if emit {
            Tier::new(name, expr)
        } else {
            Tier::hidden(name, expr)
        };
        self.builder.push(tier);
        Ok(())
    }

    /// Declare an emitted balancer, optionally with a strategy.
    #[pyo3(signature = (name, expr, kind = "leastPing"))]
    fn add_balancer(&mut self, name: &str, expr: &str, kind: &str) -> PyResult<()> {
        let kind = BalancerKind::parse(kind)
            .ok_or_else(|| PyValueError::new_err(format!("unknown balancer kind {kind}")))?;
        self.builder.push(
            Tier::new(name, expr)
                .kind(kind)
                .with_url("https://cp.cloudflare.com/generate_204")
                .with_interval(300),
        );
        Ok(())
    }

    fn set_default(&mut self, tag: &str) {
        self.builder.set_default_mut(tag);
    }

    /// Emit local SOCKS/HTTP inbounds, so the config runs on its own.
    ///
    /// Leave it off when handing a profile to a client: the client adds its own
    /// inbounds, and a second pair would collide on the ports.
    fn set_inbounds(&mut self, yes: bool) {
        self.builder.inbounds = yes;
    }

    /// `"name -> expr -> N nodes"` for every tier, declaration order.
    fn summary(&self, nodes: Vec<PyNode>) -> PyResult<Vec<(String, String, usize)>> {
        self.builder.summary(&to_nodes(nodes)).map_err(err)
    }

    /// Every emitted balancer as its own config (subscription array).
    fn export(
        &self,
        py: Python<'_>,
        nodes: Vec<PyNode>,
        original: Vec<Py<PyAny>>,
    ) -> PyResult<String> {
        let original = read_json_values(py, original)?;
        self.builder
            .export(&to_nodes(nodes), &original)
            .map(|e| e.json)
            .map_err(err)
    }

    /// All balancers inside one config: `(json, default_tag)`.
    fn export_single(
        &self,
        py: Python<'_>,
        nodes: Vec<PyNode>,
        original: Vec<Py<PyAny>>,
    ) -> PyResult<(String, String)> {
        let original = read_json_values(py, original)?;
        let out = self
            .builder
            .export_single(&to_nodes(nodes), &original)
            .map_err(err)?;
        Ok((out.json, out.default_tag))
    }

    /// The same export as one config object instead of an array.
    ///
    /// A subscription is a JSON array of profiles, which is what clients expect
    /// when they fetch one; a config file is a single object. Importing an
    /// array works in some clients and silently does nothing in others.
    fn export_single_object(
        &self,
        py: Python<'_>,
        nodes: Vec<PyNode>,
        original: Vec<Py<PyAny>>,
    ) -> PyResult<(String, String)> {
        let original = read_json_values(py, original)?;
        let out = self
            .builder
            .export_single(&to_nodes(nodes), &original)
            .map_err(err)?;
        Ok((out.plain, out.default_tag))
    }

    fn warnings(&self, nodes: Vec<PyNode>) -> PyResult<Vec<String>> {
        let inner = to_nodes(nodes);
        let plan = self.builder.plan(&inner).map_err(err)?;
        Ok(plan.validate(&inner).iter().map(|w| w.0.clone()).collect())
    }
}

fn read_json_values(py: Python<'_>, items: Vec<Py<PyAny>>) -> PyResult<Vec<serde_json::Value>> {
    items
        .iter()
        .map(|item| {
            let json: String = item.bind(py).extract()?;
            serde_json::from_str(&json).map_err(err)
        })
        .collect()
}

// ---------------------------------------------------------------- filters

/// Drop duplicates.
///
/// `mode="strict"` compares every parameter that changes the bytes on the wire;
/// `mode="basic"` (the default) is the loose `protocol+address+uuid+port+sni+
/// security`, and `mode="endpoint"` is address and port alone.
#[pyfunction]
#[pyo3(signature = (nodes, mode = "basic"))]
fn dedup(nodes: Vec<PyNode>, mode: &str) -> PyResult<Vec<PyNode>> {
    let nodes = to_nodes(nodes);
    Ok(from_nodes(match mode.trim().to_ascii_lowercase().as_str() {
        "strict" | "полный" => crate::filter::dedup_strict(nodes),
        "basic" | "простой" => crate::filter::dedup(nodes),
        "endpoint" | "адрес" => crate::filter::dedup_by_endpoint(nodes),
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown dedup mode {other}: strict, basic or endpoint"
            )))
        }
    }))
}

/// Keep only nodes whose address falls inside one of the given IPs/CIDRs.
#[pyfunction]
fn filter_by_cidr(nodes: Vec<PyNode>, cidrs: Vec<String>) -> PyResult<Vec<PyNode>> {
    let nets = cidrs
        .iter()
        .map(|c| crate::filter::ip::IpMatcher::parse(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    Ok(from_nodes(crate::filter::keep_ips(to_nodes(nodes), &nets)))
}

/// Drop nodes whose address falls inside one of the given IPs/CIDRs.
#[pyfunction]
fn exclude_cidr(nodes: Vec<PyNode>, cidrs: Vec<String>) -> PyResult<Vec<PyNode>> {
    let nets = cidrs
        .iter()
        .map(|c| crate::filter::ip::IpMatcher::parse(c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    Ok(from_nodes(crate::filter::drop_ips(to_nodes(nodes), &nets)))
}

/// Drop placeholder entries (`0.0.0.0`, `1.1.1.1`, loopback, metadata...).
#[pyfunction]
fn clean_stubs(nodes: Vec<PyNode>) -> Vec<PyNode> {
    from_nodes(crate::filter::stubs::clean(to_nodes(nodes)))
}

/// Keep only nodes with one of these exit countries (requires `mark_country`).
#[pyfunction]
fn filter_by_country(nodes: Vec<PyNode>, countries: Vec<String>) -> Vec<PyNode> {
    from_nodes(crate::geo::filter_by_country(to_nodes(nodes), &countries))
}

/// Turn a numeric selection (`"1-5,8"`) into 0-based indices.
#[pyfunction]
fn parse_selection(text: &str, count: usize) -> PyResult<Vec<usize>> {
    crate::select::parse_selection(text, count).map_err(err)
}

// ---------------------------------------------------------------- probes

/// One probe outcome.
#[pyclass(module = "v2keylib", name = "ProbeResult")]
#[derive(Clone)]
pub struct PyProbeResult {
    #[pyo3(get)]
    pub index: usize,
    #[pyo3(get)]
    pub alive: bool,
    #[pyo3(get)]
    pub elapsed_ms: u64,
    #[pyo3(get)]
    pub error: Option<String>,
}

/// Check reachability; returns one result per node, in input order.
#[pyfunction]
#[pyo3(signature = (nodes, kind = "tcp", timeout = 3.0, concurrency = 64))]
fn probe(
    py: Python<'_>,
    nodes: Vec<PyNode>,
    kind: &str,
    timeout: f64,
    concurrency: usize,
) -> PyResult<Vec<PyProbeResult>> {
    let kind = ProbeKind::parse(kind).map_err(err)?;
    let opts = ProbeOptions {
        timeout: std::time::Duration::from_secs_f64(timeout.max(0.1)),
        concurrency,
        ..Default::default()
    };
    let nodes = to_nodes(nodes);
    let rt = runtime()?;
    // the GIL is released while sockets are open
    let results = py.detach(|| rt.block_on(pipeline::probe_all(nodes, kind, &opts)));
    Ok(results
        .into_iter()
        .map(|r| PyProbeResult {
            index: r.index,
            alive: r.alive,
            elapsed_ms: r.elapsed_ms,
            error: r.error,
        })
        .collect())
}

// ---------------------------------------------------------------- geo

/// A geo database: XRay `geoip.dat`, MaxMind `.mmdb`, or a remote IP-API.
#[pyclass(module = "v2keylib", name = "GeoDb")]
pub struct PyGeoDb {
    inner: GeoDb,
}

#[pymethods]
impl PyGeoDb {
    /// Load a local file; the format is detected from its content, not its name.
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        GeoDb::load(path)
            .map(|inner| PyGeoDb { inner })
            .map_err(err)
    }

    /// Use a remote IP-API (`"ip-api.com"`, `"ipwho.is"`, `"ipapi.co"`).
    #[staticmethod]
    fn remote(provider: &str) -> PyResult<Self> {
        let provider = crate::geo::api::Provider::parse(provider).map_err(err)?;
        GeoDb::remote(provider)
            .map(|inner| PyGeoDb { inner })
            .map_err(err)
    }

    /// `"geoip.dat (XRay protobuf)"`, `"MaxMind .mmdb"` or the API host.
    #[getter]
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    #[getter]
    fn is_remote(&self) -> bool {
        self.inner.is_remote()
    }

    fn country(&self, ip: &str) -> PyResult<Option<String>> {
        let parsed: std::net::IpAddr = ip.parse().map_err(|_| {
            PyValueError::new_err(format!("not an IP address: {ip}"))
        })?;
        Ok(self
            .inner
            .as_local()
            .and_then(|r| r.country_of(parsed)))
    }

    /// Stamp `country` on every node in place.
    ///
    /// Returns a dict with the country histogram, the cascade split against
    /// `entry_country`, and the share of nodes that leave it.
    #[pyo3(signature = (nodes, entry_country = None))]
    fn annotate(
        &self,
        py: Python<'_>,
        nodes: &Bound<'_, PyList>,
        entry_country: Option<String>,
    ) -> PyResult<Py<PyDict>> {
        let Some(resolver) = self.inner.as_local() else {
            return Err(PyRuntimeError::new_err(
                "annotate needs a local database; use GeoDb.cascade for remote sources",
            ));
        };
        let mut items: Vec<PyRefMut<'_, PyNode>> = Vec::with_capacity(nodes.len());
        for item in nodes.try_iter()? {
            items.push(item?.extract::<PyRefMut<'_, PyNode>>()?);
        }
        let mut inner: Vec<Node> = items.iter().map(|n| n.inner.clone()).collect();
        let kinds = crate::geo::annotate(&mut inner, resolver, entry_country.as_deref());
        // write the stamps back into the caller's own objects
        for (item, node) in items.iter_mut().zip(inner.iter()) {
            item.set_country(node.extra.get("country").cloned());
        }

        let dict = PyDict::new(py);
        dict.set_item("countries", counts_by_country(&inner))?;
        let mut direct = 0usize;
        let mut cross = 0usize;
        let mut unknown = 0usize;
        for kind in &kinds {
            match kind {
                Cascade::Direct => direct += 1,
                Cascade::Cross => cross += 1,
                Cascade::Unknown => unknown += 1,
            }
        }
        dict.set_item("direct", direct)?;
        dict.set_item("cross", cross)?;
        dict.set_item("unknown", unknown)?;
        let known = direct + cross;
        dict.set_item(
            "cross_share",
            if known == 0 { 0.0 } else { cross as f64 / known as f64 },
        )?;
        Ok(dict.unbind())
    }

    /// This machine's public IP, via the echo services in `ECHO_SERVICES`.
    fn local_ip(&self, py: Python<'_>) -> PyResult<String> {
        let rt = runtime()?;
        let ip = py.detach(|| rt.block_on(self.inner.local_ip())).map_err(err)?;
        Ok(ip.to_string())
    }

    /// The entry country of this machine: its own public IP, then a lookup.
    ///
    /// A local database cannot answer this on its own — it has no record for a
    /// loopback address — so the machine's *public* IP is looked up instead.
    fn entry_country(&self, py: Python<'_>) -> PyResult<Option<String>> {
        let rt = runtime()?;
        let country = py
            .detach(|| rt.block_on(self.inner.entry_country()))
            .map_err(err)?;
        Ok(country)
    }

    /// Cascade for a whole config; returns a summary dict plus per-node rows.
    #[pyo3(signature = (config_text, entry_country = None, concurrency = 16))]
    fn cascade(
        &self,
        py: Python<'_>,
        config_text: &str,
        entry_country: Option<String>,
        concurrency: usize,
    ) -> PyResult<Py<PyDict>> {
        let rt = runtime()?;
        let report = py.detach(|| {
            rt.block_on(
                self.inner
                    .cascade(config_text, entry_country.as_deref(), concurrency),
            )
        });
        let report = report.map_err(err)?;
        report_to_py(py, report)
    }
}

fn counts_by_country(nodes: &[Node]) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for node in nodes {
        let key = node
            .extra
            .get("country")
            .cloned()
            .unwrap_or_else(|| "??".into());
        *out.entry(key).or_default() += 1;
    }
    out
}

fn cascade_name(c: &Cascade) -> &'static str {
    match c {
        Cascade::Direct => "direct",
        Cascade::Cross => "cross",
        Cascade::Unknown => "unknown",
    }
}

fn report_to_py(
    py: Python<'_>,
    report: crate::geo::cascade::CascadeReport,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item(
        "entry_country",
        report.entry_country.clone().unwrap_or_default(),
    )?;
    dict.set_item("direct", report.summary.get("Direct").copied().unwrap_or(0))?;
    dict.set_item("cross", report.summary.get("Cross").copied().unwrap_or(0))?;
    dict.set_item("unknown", report.summary.get("Unknown").copied().unwrap_or(0))?;
    dict.set_item("unresolved", report.unresolved)?;
    dict.set_item("cross_share", report.cross_share())?;

    let rows = PyList::empty(py);
    for row in &report.nodes {
        let item = PyDict::new(py);
        item.set_item("index", row.index + 1)?;
        item.set_item("address", &row.address)?;
        item.set_item(
            "ip",
            row.ip.map(|ip| ip.to_string()).unwrap_or_default(),
        )?;
        item.set_item("country", row.country.clone().unwrap_or_default())?;
        item.set_item("city", row.city.clone().unwrap_or_default())?;
        item.set_item("cascade", cascade_name(&row.cascade))?;
        item.set_item("anycast", row.anycast)?;
        // the subscription's own name for the node: these often name a country
        // the node does not actually exit from
        item.set_item("label", row.label.clone())?;
        item.set_item("claimed_route", row.claimed_route.clone())?;
        item.set_item("claimed_exit", row.claimed_exit())?;
        item.set_item("contradicts", row.label_contradicts_geodata())?;
        rows.append(item)?;
    }

    let routes = PyList::empty(py);
    for route in report.routes() {
        let item = PyDict::new(py);
        item.set_item("entry", route.entry.clone())?;
        item.set_item("exit", route.exit.clone())?;
        item.set_item("count", route.count)?;
        item.set_item("describe", route.describe())?;
        routes.append(item)?;
    }
    dict.set_item("routes", routes)?;
    dict.set_item("verdict", report.verdict())?;
    dict.set_item("nodes", rows)?;
    Ok(dict.unbind())
}

// ---------------------------------------------------------------- subscription

/// Fetch and parse a subscription URL.
///
/// `xhwid` is the `X-Hwid` header value: sixteen characters to send one,
/// `"none"` to send no header at all, and nothing for the default placeholder.
#[pyfunction]
#[pyo3(signature = (url, xhwid = None, clean_stubs = true, timeout = 20.0))]
fn fetch(
    py: Python<'_>,
    url: &str,
    xhwid: Option<&str>,
    clean_stubs: bool,
    timeout: f64,
) -> PyResult<Vec<PyNode>> {
    let mut opts = subscription::FetchOptions {
        clean_stubs,
        timeout: std::time::Duration::from_secs_f64(timeout.max(1.0)),
        ..Default::default()
    };
    if let Some(hwid) = xhwid.filter(|h| !h.is_empty()) {
        opts = opts.with_xhwid_text(Some(hwid)).map_err(err)?;
    }
    let rt = runtime()?;
    let sub = py
        .detach(|| rt.block_on(subscription::fetch(url, &opts)))
        .map_err(err)?;
    Ok(from_nodes(sub.nodes()))
}

/// Parse a subscription body without touching the network.
#[pyfunction]
fn parse_subscription(text: &str) -> PyResult<Vec<PyNode>> {
    subscription::parse_body(text)
        .map(|s| from_nodes(s.nodes()))
        .map_err(err)
}

/// Generate the 16-character `X-Hwid` header value.
#[pyfunction]
fn generate_xhwid() -> String {
    subscription::XHwid::generate().into_string()
}

// ---------------------------------------------------------------- pipeline

/// Everything in one call: read, filter, probe, render.
#[pyfunction]
#[pyo3(signature = (source, format = "xray", balancer = None, probe_kind = None,
                     whitelist = None, blacklist = None, countries = None,
                     dedup = true, clean = true, limit = 0, timeout = 3.0,
                     concurrency = 64))]
#[allow(clippy::too_many_arguments)]
fn convert(
    py: Python<'_>,
    source: &str,
    format: &str,
    balancer: Option<String>,
    probe_kind: Option<String>,
    whitelist: Option<Vec<String>>,
    blacklist: Option<Vec<String>>,
    countries: Option<Vec<String>>,
    dedup: bool,
    clean: bool,
    limit: usize,
    timeout: f64,
    concurrency: usize,
) -> PyResult<String> {
    let is_url = source.starts_with("http://") || source.starts_with("https://");
    let input = if is_url {
        crate::pipeline::Input::Url(source.to_string())
    } else {
        let text = std::fs::read_to_string(source).map_err(err)?;
        crate::pipeline::Input::Text(text)
    };

    let mut pipe = crate::pipeline::Pipeline::new()
        .input(input)
        .dedup(dedup);
    for cidr in whitelist.unwrap_or_default() {
        pipe = pipe.whitelist_cidrs(&cidr).map_err(err)?;
    }
    for cidr in blacklist.unwrap_or_default() {
        pipe = pipe.blacklist_cidrs(&cidr).map_err(err)?;
    }
    if let Some(countries) = countries {
        pipe = pipe.filter_by_country(&countries);
    }
    if let Some(kind) = probe_kind {
        pipe = pipe.probe_with(
            ProbeKind::parse(&kind).map_err(err)?,
            ProbeOptions {
                timeout: std::time::Duration::from_secs_f64(timeout.max(0.1)),
                concurrency,
                ..Default::default()
            },
        );
    }
    if limit > 0 {
        pipe = pipe.limit(limit);
    }

    let rt = runtime()?;
    let nodes = py.detach(|| rt.block_on(pipe.run_with_nodes())).map_err(err)?;
    let nodes = if clean {
        crate::filter::stubs::clean(nodes)
    } else {
        nodes
    };
    if nodes.is_empty() {
        return Err(PyRuntimeError::new_err("nothing survived the filters"));
    }
    match balancer {
        Some(name) => config::render(
            format_from(format)?,
            &nodes,
            Some(&config::BalancerSpec::new(name, BalancerKind::UrlTest)),
        )
        .map_err(err),
        None => match format.to_ascii_lowercase().as_str() {
            "links" => links::render_all(&nodes).map_err(err),
            _ => config::render(format_from(format)?, &nodes, None).map_err(err),
        },
    }
}

// ---------------------------------------------------------------- module

#[pymodule]
fn v2keylib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyNode>()?;
    m.add_class::<PyPlan>()?;
    m.add_class::<PyGeoDb>()?;
    m.add_class::<PyProbeResult>()?;

    m.add_function(wrap_pyfunction!(parse_link, m)?)?;
    m.add_function(wrap_pyfunction!(parse_links, m)?)?;
    m.add_function(wrap_pyfunction!(to_links, m)?)?;
    m.add_function(wrap_pyfunction!(detect_format, m)?)?;
    m.add_function(wrap_pyfunction!(parse_config, m)?)?;
    m.add_function(wrap_pyfunction!(to_config, m)?)?;
    m.add_function(wrap_pyfunction!(config_groups, m)?)?;
    m.add_function(wrap_pyfunction!(flatten_config, m)?)?;
    m.add_function(wrap_pyfunction!(dedup, m)?)?;
    m.add_function(wrap_pyfunction!(filter_by_cidr, m)?)?;
    m.add_function(wrap_pyfunction!(exclude_cidr, m)?)?;
    m.add_function(wrap_pyfunction!(clean_stubs, m)?)?;
    m.add_function(wrap_pyfunction!(filter_by_country, m)?)?;
    m.add_function(wrap_pyfunction!(parse_selection, m)?)?;
    m.add_function(wrap_pyfunction!(probe, m)?)?;
    m.add_function(wrap_pyfunction!(fetch, m)?)?;
    m.add_function(wrap_pyfunction!(parse_subscription, m)?)?;
    m.add_function(wrap_pyfunction!(generate_xhwid, m)?)?;
    m.add_function(wrap_pyfunction!(convert, m)?)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

/// Keep the probe module reachable from Rust users compiling without `python`.
#[allow(dead_code)]
fn _probe_reexport(kind: ProbeKind) -> &'static str {
    kind.as_str()
}