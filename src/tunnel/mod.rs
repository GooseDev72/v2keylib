//! Measure what a node *really* exits through, by running it.
//!
//! Everything else in this crate decides a country from the address written in
//! the link. That is the country of the machine you dial, which is the same
//! thing as the exit country only when the node is a plain endpoint. For
//! anything behind a CDN it is not: `146.75.59.79` is a Fastly front, and
//! whatever sits behind it may well be anywhere.
//!
//! So this module does the honest thing — spin the node up, ask an API who it
//! thinks we are, shut it down. One short-lived XRay process per node, killed
//! as soon as the answer arrives.
//!
//! ```no_run
//! # async fn run(link: &str) -> v2keylib::Result<()> {
//! let node = v2keylib::links::parse(link)?;
//! let xray = v2keylib::tunnel::Xray::fetch().await?;
//! let seen = v2keylib::tunnel::exit_ip(&node, &xray).await?;
//! println!("{} exits as {}", link, seen.ip);
//! # Ok(())
//! # }
//! ```
//!
//! Two costs worth knowing before reaching for this. Every node costs a process
//! spawn and a full handshake, so it is orders of magnitude slower than a
//! GeoIP lookup and pointless for a list you already trust. And it sends traffic
//! through third-party endpoints that are, by construction, the kind of host a
//! free subscription is not supposed to be connecting to.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};

use crate::config::xray;
use crate::error::{Error, Result};
use crate::node::Node;

/// Where the API is asked "who am I".
///
/// Deliberately a plain endpoint with no IP in the path: the whole point is to
/// let the API report the address the request arrived from, which is the tunnel's
/// exit. Naming an IP would ask about that IP instead.
const EXIT_URL: &str = "http://ip-api.com/json/?fields=status,message,query,countryCode,country,city,isp,proxy,hosting";

/// Fallbacks, in order, for when ip-api has nothing to give.
///
/// The rate limit on ip-api is per source address and it is a low one: forty-five
/// requests a minute. A run over a thousand nodes therefore *cannot* be answered
/// by it, and every node past the forty-fifth second of every minute came back
/// as "no answer through…" — a healthy node written down as dead, and then
/// remembered as dead by the cache.
///
/// The services here have no such limit, but the first three answer with a bare
/// address and no country. That is a fair trade: a node that is alive but whose
/// country is unknown beats a node that is declared dead because we asked the
/// wrong API too quickly.
const EXIT_FALLBACKS: &[&str] = &[
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
];

/// How long one attempt gets, handshake included.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// XRay release to fetch when no version is pinned.
const DEFAULT_VERSION: &str = "v26.10.21";

/// A locally managed XRay binary.
pub struct Xray {
    path: PathBuf,
    version: String,
}

impl Xray {
    /// An already-installed binary, if the caller has one.
    ///
    /// Worth trying first: it skips a 20 MB download, and a system XRay may be
    /// newer than anything pinned here.
    pub fn system() -> Option<Self> {
        which("xray").map(|path| Self {
            path,
            version: "system".into(),
        })
    }

    /// Where downloaded binaries are kept.
    ///
    /// Honours `V2KEYLIB_XRAY_DIR`, then the platform cache directory, and
    /// falls back to a dot-directory in `$HOME` when neither is available —
    /// which is what happens in a container with no cache env set.
    pub fn cache_dir() -> Result<PathBuf> {
        if let Ok(dir) = std::env::var("V2KEYLIB_XRAY_DIR") {
            if !dir.trim().is_empty() {
                return Ok(PathBuf::from(dir));
            }
        }
        if let Ok(dir) = std::env::var("XDG_CACHE_HOME") {
            if !dir.trim().is_empty() {
                return Ok(PathBuf::from(dir).join("v2keylib").join("xray"));
            }
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| Error::Fetch("no HOME to cache the XRay binary in".into()))?;
        Ok(PathBuf::from(home)
            .join(".cache")
            .join("v2keylib")
            .join("xray"))
    }

    /// Download and unpack the release for this machine, reusing a cached copy.
    pub async fn fetch() -> Result<Self> {
        Self::fetch_version(DEFAULT_VERSION).await
    }

    /// Same, for a pinned release tag such as `v25.9.11`.
    pub async fn fetch_version(version: &str) -> Result<Self> {
        // One directory per release: a cached binary from an older pinned
        // version must not be mistaken for the one that was asked for. Hysteria2
        // in particular is new enough that an old cached XRay simply does not
        // know the protocol.
        let dir = Self::cache_dir()?.join(version);
        let path = dir.join(binary_name());

        if path.exists() {
            return Ok(Self {
                path,
                version: version.to_string(),
            });
        }
        std::fs::create_dir_all(&dir)?;

        let asset = asset_name()?;
        let zip_url =
            format!("https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}");
        tracing::info!("downloading {zip_url}");

        let archive = download(&zip_url).await?;
        // The release publishes a digest next to every asset; checking it means a
        // tampered or truncated mirror fails here instead of executing.
        let expected = digest_for(version, &asset).await?;
        if let Some(expected) = expected {
            let got = sha256(&archive);
            if !expected.eq_ignore_ascii_case(&got) {
                return Err(Error::Fetch(format!(
                    "{asset}: sha256 {got} does not match the published {expected}"
                )));
            }
        } else {
            tracing::warn!("{asset}: no published digest, skipping the check");
        }

        let extracted = unzip_binary(&archive)?;
        // Write to a temporary name and rename, so a concurrent run never sees a
        // half-written binary and tries to exec it.
        let tmp = path.with_extension("partial");
        std::fs::write(&tmp, &extracted)?;
        set_executable(&tmp)?;
        std::fs::rename(&tmp, &path)?;

        Ok(Self {
            path,
            version: version.to_string(),
        })
    }

    /// Use a specific binary, whatever it is.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            version: "custom".into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    /// Check the binary answers, so a broken download is reported here rather
    /// than as a confusing failure to start a tunnel.
    pub async fn check(&self) -> Result<String> {
        let out = tokio::process::Command::new(&self.path)
            .arg("version")
            .output()
            .await
            .map_err(|e| Error::Fetch(format!("{}: {e}", self.path.display())))?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !out.status.success() {
            return Err(Error::Fetch(format!(
                "{} exited with {}",
                self.path.display(),
                out.status
            )));
        }
        Ok(text.lines().next().unwrap_or(&text).to_string())
    }
}

/// What the exit API reported about the tunnel.
#[derive(Clone, Debug)]
pub struct Exit {
    /// The address the API saw the request arrive from: the tunnel's exit.
    pub ip: IpAddr,
    /// ISO code, when the API had one.
    pub country: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    /// The API flagged the address as a proxy or hosting range.
    pub hosting: bool,
}

/// Ask who the node's traffic exits as.
///
/// Runs the node for the length of one HTTP request and nothing more: the
/// process is killed before this returns, including on the error paths, so a
/// dead node cannot leave a listener behind.
pub async fn exit_ip(node: &Node, xray: &Xray) -> Result<Exit> {
    exit_ip_with(node, xray, DEFAULT_TIMEOUT).await
}

/// Same, with an explicit per-attempt timeout.
pub async fn exit_ip_with(node: &Node, xray: &Xray, timeout: Duration) -> Result<Exit> {
    let outcome = tokio::time::timeout(timeout, async {
        let tunnel = Tunnel::open(node, xray).await?;
        tunnel.exit_ip().await
    })
    .await;

    match outcome {
        Ok(result) => result,
        Err(_) => Err(Error::Probe(format!(
            "no answer through {} within {timeout:?}",
            node.address
        ))),
    }
}

/// One node, running, reachable on a local SOCKS port.
///
/// This is what makes asking more than one question of a node affordable: the
/// exit-IP lookup and the site checks happen inside one XRay process, instead of
/// paying to start the node twice. The process is killed and its config removed
/// when the tunnel is dropped — including on the error paths, and on a panic —
/// so a dead node cannot leave a listener behind or a config full of credentials
/// on disk.
pub struct Tunnel {
    child: tokio::process::Child,
    socks: SocketAddr,
    dir: PathBuf,
}

impl Tunnel {
    /// Start the node and wait for its inbound to accept connections.
    pub async fn open(node: &Node, xray: &Xray) -> Result<Self> {
        let socks = free_port()?;
        let config = probe_config(node, socks);

        // The config carries node credentials, so it goes in a private directory
        // and is removed by the guard below however this function exits.
        let dir = private_dir()?;
        let config_path = dir.join("config.json");
        std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

        let mut child = tokio::process::Command::new(xray.path())
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| Error::Fetch(format!("{}: {e}", xray.path().display())))?;

        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, socks));
        if let Err(e) = wait_for_listener(&mut child, addr).await {
            let _ = child.kill().await;
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        Ok(Self {
            child,
            socks: addr,
            dir,
        })
    }

    /// The local address to point a SOCKS client at.
    pub fn socks(&self) -> SocketAddr {
        self.socks
    }

    /// Who the far end thinks we are.
    pub async fn exit_ip(&self) -> Result<Exit> {
        ask(self.socks).await
    }

    /// Which of `checks` the node can reach, asked through this tunnel.
    pub async fn check(
        &self,
        checks: &crate::checks::Checks,
        timeout: Duration,
    ) -> crate::checks::Report {
        crate::checks::ask_all(self.socks, checks, timeout).await
    }

    /// How long one request through the tunnel takes.
    ///
    /// Not a ping in the ICMP sense and not the node's ping either: it is what
    /// the user waits for, tunnel set up, TLS handshake and the far end's answer
    /// included. That is the number that decides whether a node feels fast, and
    /// the one the client will measure anyway, so measuring it here means the
    /// subscription and the client agree.
    pub async fn latency(&self, url: &str, bytes: usize, timeout: Duration) -> Option<Duration> {
        let client = checks_client(self.socks).ok()?;
        let started = std::time::Instant::now();
        let send = client
            .get(url)
            .header("Range", format!("bytes=0-{}", bytes.saturating_sub(1)))
            .send();
        let response = match tokio::time::timeout(timeout, send).await {
            Ok(Ok(response)) => response,
            _ => return None,
        };
        // Time to headers, and nothing more. Reading the body here is what made
        // one node take five and a half minutes: a proxy that drops `Range` turns
        // a "how far away is this" question into a ten-megabyte download, and it
        // does so slowly, and unbounded — the timeout covered the request but not
        // the body. Latency is the round trip; the bytes are measured separately,
        // where a slow body is the answer rather than an accident.
        drop(response);
        Some(started.elapsed())
    }

    /// Download through the tunnel and report megabits per second.
    ///
    /// A ping says nothing about a file transfer, and a 1 Mbit/s node with a
    /// beautiful ping is unusable for anything worth streaming — sitting through
    /// a film at that speed is exactly the complaint that makes people delete a
    /// whole subscription.
    ///
    /// The response is *streamed* and counted until the deadline, rather than
    /// asked for whole: a node that manages a hundred kilobytes in ten seconds
    /// has a speed, and that speed is the answer. Waiting for the full payload
    /// would time out on exactly the nodes this is here to catch, and report
    /// them as "not measured" — which is the one thing that must not happen,
    /// because unmeasured reads as "no reason to drop".
    ///
    /// The urls are tried in turn, and several are needed: measured through a
    /// proxy exit, the obvious choice (Cloudflare's speed endpoint) answers 200
    /// with an empty body, because it does not serve a known VPN exit at all. An
    /// empty 200 is a refusal dressed as a success, so it is checked for.
    pub async fn speed(&self, urls: &[String], target: usize, timeout: Duration) -> Option<f64> {
        let client = checks_client(self.socks).ok()?;
        for url in urls {
            if let Some(mbps) = self.speed_once(&client, url, target, timeout).await {
                return Some(mbps);
            }
        }
        None
    }

    async fn speed_once(
        &self,
        client: &reqwest::Client,
        url: &str,
        target: usize,
        timeout: Duration,
    ) -> Option<f64> {
        let started = std::time::Instant::now();
        let deadline = started + timeout;

        let send = client
            .get(url)
            .header("Range", format!("bytes=0-{}", target.saturating_sub(1)))
            .send();
        let response = match tokio::time::timeout(timeout, send).await {
            Ok(Ok(response)) => response,
            _ => return None,
        };
        if !response.status().is_success() {
            return None;
        }

        let mut stream = response.bytes_stream();
        let mut got = 0usize;
        // The clock starts at the *first byte*, not at the request.
        //
        // Time to first byte is the round trip and the server's thinking time —
        // that is latency, and latency is measured separately and on purpose.
        // Folding it into a "speed" makes a node with a fast pipe and a distant
        // server look slow, which is the one thing this number must not do.
        let mut first_byte = None;
        while got < target {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, futures::StreamExt::next(&mut stream)).await {
                // A truncated body is a closed connection; what arrived is what
                // we measure, and that is the honest answer for a slow link.
                Ok(None) | Err(_) => break,
                Ok(Some(Err(_))) => break,
                Ok(Some(Ok(chunk))) => {
                    first_byte.get_or_insert(std::time::Instant::now());
                    got += chunk.len();
                }
            }
        }

        let secs = match first_byte {
            Some(at) => at.elapsed().as_secs_f64(),
            None => return None,
        };
        if secs <= 0.0 || got == 0 {
            return None;
        }
        Some(got as f64 * 8.0 / secs / 1_000_000.0)
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Best effort, and deliberately not awaited: `Drop` cannot be. The child
        // also carries `kill_on_drop`, and the directory holds credentials that
        // should not outlive the run.
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Ask who we are, through a SOCKS proxy that is already running.
///
/// The counterpart to [`exit_ip`] for when something else owns the tunnel — a
/// client you have already started, or a hand-run `xray run` while debugging a
/// node. Separating this from the process management is what makes that
/// possible: the measurement does not care where the SOCKS port came from.
pub async fn exit_ip_via_socks(proxy: SocketAddr) -> Result<Exit> {
    ask(proxy).await
}

/// The API's view of the caller, made through the tunnel.
async fn ask(proxy: SocketAddr) -> Result<Exit> {
    let client = reqwest::Client::builder()
        // socks5h, not socks5: the hostname has to be resolved by the far end,
        // or we would answer "who am I" with the local network's idea of where
        // ip-api.com is rather than the tunnel's.
        .proxy(
            reqwest::Proxy::all(format!("socks5h://{proxy}"))
                .map_err(|e| Error::Probe(e.to_string()))?,
        )
        .timeout(Duration::from_secs(10))
        .user_agent("v2keylib/0.1")
        .build()
        .map_err(|e| Error::Probe(e.to_string()))?;

    let answer = client
        .get(EXIT_URL)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| Error::Probe(format!("through {proxy}: {e}")))?
        .text()
        .await
        .map_err(|e| Error::Probe(format!("through {proxy}: {e}")))?;

    // ip-api answers `{"status":"fail"}` when it refuses, which is not an error
    // code but the same refusal. Fall through on both.
    if let Ok(exit) = parse_exit(&answer) {
        return Ok(exit);
    }

    for fallback in EXIT_FALLBACKS {
        let Ok(text) = client
            .get(*fallback)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| Error::Probe(e.to_string()))
        else {
            continue;
        };
        let Ok(text) = text.text().await else {
            continue;
        };
        if let Some(exit) = parse_bare_ip(&text) {
            return Ok(exit);
        }
    }
    Err(Error::Probe("no exit service answered".into()))
}

/// A bare address, which is what the fallbacks answer with.
fn parse_bare_ip(text: &str) -> Option<Exit> {
    let ip: IpAddr = text.trim().parse().ok()?;
    Some(Exit {
        ip,
        // Unknown rather than wrong: the country comes from the api that
        // answers it, and a group keyed on it will simply not match.
        country: None,
        city: None,
        isp: None,
        hosting: false,
    })
}

fn parse_exit(text: &str) -> Result<Exit> {
    let v: Value = serde_json::from_str(text)
        .map_err(|e| Error::Probe(format!("{e}: {}", truncate(text, 200))))?;

    if v.get("status").and_then(Value::as_str) != Some("success") {
        let message = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("lookup failed");
        return Err(Error::Probe(message.to_string()));
    }

    let query = v
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Probe("the API named no address".into()))?;
    let ip: IpAddr = query
        .trim()
        .parse()
        .map_err(|_| Error::Probe(format!("not an address: {query}")))?;

    Ok(Exit {
        ip,
        country: v
            .get("countryCode")
            .and_then(Value::as_str)
            .map(str::to_string),
        city: v.get("city").and_then(Value::as_str).map(str::to_string),
        isp: v.get("isp").and_then(Value::as_str).map(str::to_string),
        hosting: ["proxy", "hosting"]
            .iter()
            .any(|k| v.get(*k).and_then(Value::as_bool).unwrap_or(false)),
    })
}

/// Just the address, for callers that only want to compare against a guess.
pub async fn exit_address(node: &Node, xray: &Xray) -> Result<IpAddr> {
    Ok(exit_ip(node, xray).await?.ip)
}

/// The verdict for one node in a batch run.
#[derive(Clone, Debug)]
pub struct Measured {
    /// Position in the input slice, so a caller can line results back up.
    pub index: usize,
    pub node: Node,
    /// `None` when the node never answered.
    ///
    /// The failure is kept as a message rather than the [`Error`] itself: the
    /// error type is not `Clone`, and a batch result wants to be cloneable so it
    /// can be kept alongside the node it describes.
    pub exit: Option<Exit>,
    pub error: Option<String>,
}

impl Measured {
    /// The measured country, when the node answered.
    pub fn country(&self) -> Option<&str> {
        self.exit.as_ref().and_then(|e| e.country.as_deref())
    }

    /// The measured exit address, when the node answered.
    pub fn exit_ip(&self) -> Option<IpAddr> {
        self.exit.as_ref().map(|e| e.ip)
    }

    pub fn is_alive(&self) -> bool {
        self.exit.is_some()
    }

    /// Stamp the measured country onto the node's `extra`, where the balancer
    /// selectors and the Python layer look for it.
    pub fn into_node(mut self) -> Node {
        if let Some(exit) = &self.exit {
            if let Some(country) = &exit.country {
                self.node.extra.insert("country".into(), country.clone());
            }
            self.node.extra.insert("exit".into(), exit.ip.to_string());
        }
        self.node
    }
}

/// How a batch run should be spread out.
#[derive(Clone, Copy, Debug)]
pub struct BatchOptions {
    /// How many XRay processes at once.
    ///
    /// Each is a separate process with its own copy of the runtime, so this is
    /// a memory decision as much as a network one — roughly 30 MB each. Six
    /// concurrent is a reasonable default for a developer machine; raise it
    /// only with the RAM to spare.
    pub concurrency: usize,
    /// Per-node budget, handshake included.
    pub timeout: Duration,
    /// Minimum gap between requests, applied across the whole batch.
    ///
    /// The API behind the tunnel rate-limits by *source* address, and there is
    /// only one of those when several nodes share an exit. A small stagger keeps
    /// a burst of siblings from tripping it. Set to zero to disable.
    pub stagger: Duration,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            concurrency: 6,
            timeout: DEFAULT_TIMEOUT,
            stagger: Duration::from_millis(250),
        }
    }
}

/// Measure many nodes, a few at a time.
///
/// Results come back in input order with a verdict for every node, including
/// the failures — a short list is the normal outcome on a free subscription, so
/// "which ones did not answer" is as useful as the answers themselves.
pub async fn exit_ips(nodes: &[Node], xray: &Xray, opts: BatchOptions) -> Vec<Measured> {
    exit_ips_with_progress(nodes, xray, opts, |_| {}).await
}

/// As [`exit_ips`], reporting each node as it finishes.
///
/// The callback fires out of order, as results arrive, which is the point: a
/// run over a few hundred nodes takes minutes, and a caller that only sees the
/// list at the end has no way to tell a slow run from a hung one.
pub async fn exit_ips_with_progress<F>(
    nodes: &[Node],
    xray: &Xray,
    opts: BatchOptions,
    on_done: F,
) -> Vec<Measured>
where
    F: FnMut(&Measured),
{
    // buffer_unordered is what caps the number of live XRay processes; the
    // mutex is what spaces their start times, which is a separate limit —
    // it belongs to the API on the far side, not to this machine.
    let gate = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
    let reporter = Arc::new(tokio::sync::Mutex::new(on_done));

    let jobs = nodes.iter().cloned().enumerate().map(|(index, node)| {
        let gate = Arc::clone(&gate);
        let reporter = Arc::clone(&reporter);
        let timeout = opts.timeout;
        let stagger = opts.stagger;
        async move {
            if !stagger.is_zero() {
                let mut next = gate.lock().await;
                tokio::time::sleep_until(*next).await;
                *next = tokio::time::Instant::now() + stagger;
            }
            let measured = match exit_ip_with(&node, xray, timeout).await {
                Ok(exit) => Measured {
                    index,
                    node,
                    exit: Some(exit),
                    error: None,
                },
                Err(e) => Measured {
                    index,
                    node,
                    exit: None,
                    error: Some(e.to_string()),
                },
            };
            // Reported before the next node starts so the lines stay in the
            // order things actually completed.
            reporter.lock().await(&measured);
            measured
        }
    });

    let mut measured: Vec<Measured> = futures::stream::iter(jobs)
        .buffer_unordered(opts.concurrency.max(1))
        .collect()
        .await;

    measured.sort_by_key(|m| m.index);
    measured
}

/// The SOCKS client the checks and the measurements share.
fn checks_client(socks: SocketAddr) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        // socks5h: the far end resolves the name, or we would be measuring the
        // local network's idea of where the speed test lives.
        .proxy(
            reqwest::Proxy::all(format!("socks5h://{socks}"))
                .map_err(|e| Error::Probe(e.to_string()))?,
        )
        .user_agent("v2keylib/0.1")
        .build()
        .map_err(|e| Error::Probe(e.to_string()))
}

/// How fast this machine's own link is, in megabits per second.
///
/// The comparison a node is judged against has to start somewhere, and the
/// obvious answer — a fixed number in a config file — is wrong twice. Too high
/// and every node is thrown away on a slow link, where the point of a proxy is
/// that it is faster than what you have; too low and a 15 Mbit/s link lets a
/// 12 Mbit/s node through as "fast".
///
/// Measured straight, once, without a proxy: same request, same endpoints, so
/// the number is directly comparable with what the nodes are measured against.
pub async fn baseline_speed(urls: &[String], bytes: usize, timeout: Duration) -> Option<f64> {
    let client = match reqwest::Client::builder()
        .user_agent("v2keylib/0.1")
        .build()
    {
        Ok(client) => client,
        Err(_) => return None,
    };
    for url in urls {
        let send = client
            .get(url)
            .header("Range", format!("bytes=0-{}", bytes.saturating_sub(1)))
            .send();
        let response = match tokio::time::timeout(timeout, send).await {
            Ok(Ok(response)) if response.status().is_success() => response,
            _ => continue,
        };
        let started = std::time::Instant::now();
        let deadline = started + timeout;
        let mut stream = response.bytes_stream();
        let mut got = 0usize;
        let mut first_byte = None;
        while got < bytes {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, futures::StreamExt::next(&mut stream)).await {
                Ok(None) | Err(_) | Ok(Some(Err(_))) => break,
                Ok(Some(Ok(chunk))) => {
                    first_byte.get_or_insert(std::time::Instant::now());
                    got += chunk.len();
                }
            }
        }
        let secs = match first_byte {
            Some(at) => at.elapsed().as_secs_f64(),
            None => continue,
        };
        if secs > 0.0 && got > 0 {
            return Some(got as f64 * 8.0 / secs / 1_000_000.0);
        }
    }
    None
}

/// A node that answered, plus what it could reach.
///
/// [`Measured`] says a node is alive; this says what that life is worth. The
/// sites are asked inside the same XRay process as the exit-IP lookup, so the
/// whole check costs what the measurement already cost.
#[derive(Clone, Debug)]
pub struct Checked {
    pub index: usize,
    pub node: Node,
    pub exit: Option<Exit>,
    pub error: Option<String>,
    pub report: crate::checks::Report,
    /// How long a request through the tunnel took.
    pub latency: Option<Duration>,
    /// Megabits per second, from a short download.
    pub mbps: Option<f64>,
}

impl Checked {
    pub fn is_alive(&self) -> bool {
        self.exit.is_some()
    }

    /// Into a [`Measured`], stamping what was learned onto the node: which
    /// sites answered (`checks=`, `unblocks=`, `ruworks=`, `social=`), how long
    /// a request took (`ping=`) and how fast a download came down (`mbps=`). All
    /// of those are what plan selectors read.
    pub fn into_measured(self, checks: &crate::checks::Checks) -> Measured {
        let Checked {
            index,
            mut node,
            exit,
            error,
            report,
            latency,
            mbps,
        } = self;
        if exit.is_some() && !report.passed.is_empty() {
            node.extra.insert("checks".into(), report.summary());
            if report.unblocks(checks) {
                node.extra.insert("unblocks".into(), "1".into());
            }
            if report.ru_works(checks) {
                node.extra.insert("ruworks".into(), "1".into());
            }
            if report.reaches_all(checks, crate::checks::Group::Social) {
                node.extra.insert("social".into(), "1".into());
            }
        }
        if let Some(latency) = latency {
            node.extra
                .insert("ping".into(), latency.as_millis().to_string());
        }
        if let Some(mbps) = mbps {
            node.extra.insert("mbps".into(), format!("{mbps:.1}"));
        }
        Measured {
            index,
            node,
            exit,
            error,
        }
    }
}

/// The extra measurements worth making on a node that answered.
///
/// Both are optional and both run *after* the answer, outside the node's
/// measurement budget: a speed test takes seconds by nature, and a node must not
/// be written off as dead because it downloaded slowly.
#[derive(Clone, Debug)]
pub struct Measurement {
    /// Where to time one request through the tunnel.
    pub ping_url: Option<String>,
    pub ping_timeout: Duration,
    /// Where to download a short burst, in the order they should be tried.
    pub speed_urls: Vec<String>,
    pub speed_timeout: Duration,
    /// Never expires, and answers with that many bytes.
    pub ping_bytes: usize,
    pub speed_bytes: usize,
    pub check_timeout: Duration,
    /// Exit countries whose nodes still need the site checks.
    ///
    /// The checks exist for one reason: to prove a node gets past the blocking
    /// that a Russian-looking exit suffers from. A node that exits in Finland
    /// does not need to prove that — it is not subject to it — and asking anyway
    /// costs requests and, worse, throws away good nodes when a site answers
    /// badly for a moment. So the list names the exits that do need proving;
    /// empty means "every node", which is the old behaviour.
    pub unblocking_countries: Vec<String>,
    /// Ask the social group even when the exit is clean.
    ///
    /// The unblocking checks are about censorship at the exit, so a Finnish node
    /// is not asked. The social group is about the service being reachable from
    /// *this* path, which has nothing to do with the exit country, so it is
    /// asked everywhere. Keeping it separate also means a clean exit pays for
    /// the social requests once, not for every check a second time.
    pub social_checks: bool,
}

impl Default for Measurement {
    fn default() -> Self {
        Self {
            ping_url: None,
            ping_timeout: Duration::from_secs(5),
            speed_urls: Vec::new(),
            speed_timeout: Duration::from_secs(10),
            ping_bytes: 1_000_000,
            speed_bytes: 8_000_000,
            check_timeout: Duration::from_secs(6),
            unblocking_countries: Vec::new(),
            social_checks: false,
        }
    }
}

impl Measurement {
    /// Whether this exit still has to prove that it unblocks anything.
    ///
    /// An unknown country is not a free pass: the country is unknown because the
    /// lookup failed, not because the exit is clean, so the check is the only
    /// evidence there is.
    pub fn requires_unblocking(&self, exit: &Exit) -> bool {
        let Some(country) = exit.country.as_deref() else {
            return true;
        };
        self.unblocking_countries.is_empty()
            || self
                .unblocking_countries
                .iter()
                .any(|c| c.eq_ignore_ascii_case(country))
    }

    /// How long the latency request asks for, and how long the speed one.
    pub fn sizes(&self) -> (usize, usize) {
        (self.ping_bytes, self.speed_bytes)
    }
}

/// Measure many nodes and ask each of them what it can reach.
///
/// Same batching, same ordering and the same progress callback as
/// [`exit_ips_with_progress`] — the difference is that each node's tunnel stays
/// up for the site checks, and the latency and speed are taken inside it.
pub async fn exit_ips_checked<F>(
    nodes: &[Node],
    xray: &Xray,
    opts: BatchOptions,
    checks: &crate::checks::Checks,
    measure: Measurement,
    on_done: F,
) -> Vec<Checked>
where
    F: FnMut(&Checked),
{
    let gate = Arc::new(tokio::sync::Mutex::new(tokio::time::Instant::now()));
    let reporter = Arc::new(tokio::sync::Mutex::new(on_done));

    let jobs = nodes.iter().cloned().enumerate().map(|(index, node)| {
        let gate = Arc::clone(&gate);
        let reporter = Arc::clone(&reporter);
        let timeout = opts.timeout;
        let stagger = opts.stagger;
        let measure = measure.clone();
        async move {
            if !stagger.is_zero() {
                let mut next = gate.lock().await;
                tokio::time::sleep_until(*next).await;
                *next = tokio::time::Instant::now() + stagger;
            }
            // The budget covers the question "does this node work at all".
            // Latency and speed come after it, on their own clocks, because a
            // slow download must not turn into a dead node.
            let tunnel = tokio::time::timeout(timeout, Tunnel::open(&node, xray)).await;
            let checked = match tunnel {
                Err(_) => Checked {
                    index,
                    node: node.clone(),
                    exit: None,
                    error: Some(format!(
                        "no answer through {} within {timeout:?}",
                        node.address
                    )),
                    report: Default::default(),
                    latency: None,
                    mbps: None,
                },
                Ok(Err(e)) => Checked {
                    index,
                    node,
                    exit: None,
                    error: Some(e.to_string()),
                    report: Default::default(),
                    latency: None,
                    mbps: None,
                },
                Ok(Ok(tunnel)) => {
                    let exit = tokio::time::timeout(timeout, tunnel.exit_ip()).await;
                    match exit {
                        Ok(Ok(exit)) => {
                            // A clean exit skips the site checks entirely and
                            // goes straight to ping and speed: it was never
                            // asked to prove anything, only to work.
                            let proving = measure.requires_unblocking(&exit);
                            let report = if proving {
                                tunnel.check(checks, measure.check_timeout).await
                            } else if measure.social_checks {
                                // Only the social group: the unblocking and
                                // Russian-reachability questions are about the
                                // exit country, and this one is not.
                                let social = checks
                                    .clone()
                                    .narrow(&[crate::checks::Group::Social]);
                                if social.is_empty() {
                                    Default::default()
                                } else {
                                    tunnel.check(&social, measure.check_timeout).await
                                }
                            } else {
                                Default::default()
                            };
                            let (latency, mbps) = if proving && report.passed.is_empty() {
                                // Nothing answered, so there is nothing to
                                // measure: this node is already out.
                                (None, None)
                            } else {
                                let (ping_bytes, speed_bytes) = measure.sizes();
                                let latency = match &measure.ping_url {
                                    Some(url) => {
                                        tunnel.latency(url, ping_bytes, measure.ping_timeout).await
                                    }
                                    None => None,
                                };
                                let mbps = match measure.speed_urls.is_empty() {
                                    true => None,
                                    false => {
                                        tunnel
                                            .speed(
                                                &measure.speed_urls,
                                                speed_bytes,
                                                measure.speed_timeout,
                                            )
                                            .await
                                    }
                                };
                                (latency, mbps)
                            };
                            Checked {
                                index,
                                node,
                                exit: Some(exit),
                                error: None,
                                report,
                                latency,
                                mbps,
                            }
                        }
                        Ok(Err(e)) => Checked {
                            index,
                            node,
                            exit: None,
                            error: Some(e.to_string()),
                            report: Default::default(),
                            latency: None,
                            mbps: None,
                        },
                        Err(_) => {
                            let error =
                                format!("no answer through {} within {timeout:?}", node.address);
                            Checked {
                                index,
                                node,
                                exit: None,
                                error: Some(error),
                                report: Default::default(),
                                latency: None,
                                mbps: None,
                            }
                        }
                    }
                }
            };
            reporter.lock().await(&checked);
            checked
        }
    });

    let mut checked: Vec<Checked> = futures::stream::iter(jobs)
        .buffer_unordered(opts.concurrency.max(1))
        .collect()
        .await;
    checked.sort_by_key(|c| c.index);
    checked
}

/// The smallest config that runs one node: a local SOCKS listener and the node
/// as the only outbound.
///
/// No balancers, no observatory, no sniffing — nothing that would outlive the
/// request or slow the handshake down.
fn probe_config(node: &Node, socks_port: u16) -> Value {
    let mut outbound = xray::outbound_for(node, "proxy");
    if let Value::Object(map) = &mut outbound {
        map.insert("tag".into(), json!("proxy"));
    }
    json!({
        "log": { "loglevel": "error" },
        "inbounds": [{
            "tag": "in",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [outbound, { "tag": "direct", "protocol": "freedom" }]
    })
}

/// Wait for the SOCKS port to accept, or for the process to give up.
///
/// Poll rather than parse XRay's log: the log says what it wants to say, and a
/// refused connect plus a live process is the portable signal.
async fn wait_for_listener(child: &mut tokio::process::Child, addr: SocketAddr) -> Result<()> {
    let deadline = tokio::time::Instant::now() + DEFAULT_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Error::Probe(format!("xray exited with {status}")));
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Probe(format!("xray never listened on {addr}")));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A port nothing is using right now.
///
/// Bound and released rather than left open: holding it while XRay starts is the
/// one way to guarantee a collision. The window between release and XRay's bind
/// is small, and a lost race surfaces as a clean "xray exited" rather than
/// anything silent.
fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// A directory only this user can read, for the config with credentials in it.
fn private_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("v2keylib-probe-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir)?;
    restrict(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------- the binary

/// The release asset for this machine's OS and architecture.
///
/// The naming is XRay's own, not a convention: `Xray-linux-64.zip`,
/// `Xray-macos-arm64-v8a.zip`, `Xray-windows-64.zip`. ARM additionally carries
/// a minimum-version suffix, so 32-bit ARM is ambiguous between v5, v6 and v7a —
/// the most capable is chosen, since a core that is too old simply will not run.
pub fn asset_name() -> Result<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let tag = match (os, arch) {
        ("linux", "x86_64") => "linux-64",
        ("linux", "x86") => "linux-32",
        ("linux", "aarch64") => "linux-arm64-v8a",
        ("linux", "arm") => "linux-arm32-v7a",
        ("linux", "powerpc64") => "linux-ppc64",
        ("linux", "s390x") => "linux-s390x",
        ("linux", "riscv64") => "linux-riscv64",
        ("linux", "mips") => "linux-mips",
        ("macos", "x86_64") => "macos-64",
        ("macos", "aarch64") => "macos-arm64-v8a",
        ("windows", "x86_64") => "windows-64",
        ("windows", "x86") => "windows-32",
        ("windows", "aarch64") => "windows-arm64-v8a",
        (other_os, other_arch) => {
            return Err(Error::Fetch(format!(
                "no XRay release for {other_os}/{other_arch}; \
                 install XRay yourself and pass Xray::from_path"
            )))
        }
    };
    Ok(format!("Xray-{tag}.zip"))
}

/// Executable name on this platform.
fn binary_name() -> &'static str {
    if cfg!(windows) {
        "xray.exe"
    } else {
        "xray"
    }
}

async fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("v2keylib/0.1")
        .build()
        .map_err(|e| Error::Fetch(e.to_string()))?;
    let bytes = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Fetch(format!("{url}: {e}")))?
        .error_for_status()
        .map_err(|e| Error::Fetch(format!("{url}: {e}")))?
        .bytes()
        .await
        .map_err(|e| Error::Fetch(format!("{url}: {e}")))?;
    Ok(bytes.to_vec())
}

/// The published SHA-256 for an asset, if the release carries one.
async fn digest_for(version: &str, asset: &str) -> Result<Option<String>> {
    let url = format!("https://github.com/XTLS/Xray-core/releases/download/{version}/{asset}.dgst");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("v2keylib/0.1")
        .build()
        .map_err(|e| Error::Fetch(e.to_string()))?;

    let Ok(resp) = client.get(url).send().await else {
        return Ok(None);
    };
    if !resp.status().is_success() {
        return Ok(None);
    }
    let text = resp.text().await.unwrap_or_default();

    Ok(text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("SHA2-256")
            .then(|| value.trim().to_string())
    }))
}

/// Pull the executable out of a release archive.
fn unzip_binary(archive: &[u8]) -> Result<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive))
        .map_err(|e| Error::Fetch(format!("not a zip archive: {e}")))?;

    // The archive also holds geoip.dat and the docs; only the binary is wanted,
    // and matching by name rather than by position keeps that true across
    // releases that reorder entries.
    let wanted = binary_name();
    use std::io::Read;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| Error::Fetch(format!("archive entry {i}: {e}")))?;
        let name = entry.name().to_string();
        let base = name.rsplit('/').next().unwrap_or(&name).to_string();
        if base.eq_ignore_ascii_case(wanted) {
            let mut out = Vec::new();
            entry
                .read_to_end(&mut out)
                .map_err(|e| Error::Fetch(format!("{base}: {e}")))?;
            return Ok(out);
        }
    }
    Err(Error::Fetch(format!("no {wanted} inside the archive")))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max).collect();
    format!("{cut}…")
}
