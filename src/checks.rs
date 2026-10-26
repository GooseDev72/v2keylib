//! What a node can actually reach, asked through the node itself.
//!
//! A node that answers "who am I" is alive. That is not the same as useful:
//! half the free subscriptions answer from an address that cannot load a
//! single page, and the user finds out in the client, on the phone, where it
//! matters least. So after a node answers, a handful of well-chosen URLs are
//! fetched through it and the answers are kept.
//!
//! Three questions, and they are different:
//!
//! * **alive** — does the tunnel carry an ordinary HTTPS request at all;
//! * **ru works** — is the node usable *from* Russia, which is where a session
//!   usually starts, and which most free nodes are blocked by;
//! * **unblocks** — does it reach what is actually blocked.
//!
//! The third one is the reason to keep the node at all. A node that unblocks
//! nothing is a node with no purpose in the subscription, so it goes. What to do
//! about AI services is deliberately *not* answered here: whether Gemini works is
//! a question about an account, a region and a login, not about a URL, so the
//! providers who say their AI configs work are taken at their word and nobody
//! second-guesses them.

use std::net::SocketAddr;
use std::time::Duration;

/// Which question a URL answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    /// Does the tunnel carry a plain HTTPS request.
    Alive,
    /// Does it work from Russia, where a session usually starts.
    RuWorking,
    /// Does it reach what is blocked. At least one of these, or the node goes.
    Unblocking,
    /// Does it reach *every* social network the social group promises.
    ///
    /// Unlike the unblocking group this is all-or-nothing: the group exists for
    /// people who need Instagram, WhatsApp, Telegram, Meta, TikTok and Facebook
    /// at the same time, so reaching one of them proves nothing.
    Social,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Alive => "alive",
            Group::RuWorking => "ru",
            Group::Unblocking => "unblocks",
            Group::Social => "social",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "alive" | "isalive" | "живой" => Some(Group::Alive),
            "ru" | "isruworking" | "из россии" => Some(Group::RuWorking),
            "unblocks" | "unblocking" | "isunblocking" | "обход" => Some(Group::Unblocking),
            "social" | "socials" | "соцсети" => Some(Group::Social),
            _ => None,
        }
    }

    /// Every group, in the order they are asked: cheap and broad first, and the
    /// decisive question last, so a node that fails to carry a request at all
    /// costs one attempt instead of sixteen.
    pub const ALL: [Group; 4] = [
        Group::Alive,
        Group::RuWorking,
        Group::Unblocking,
        Group::Social,
    ];
}

/// What "this URL worked" means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    /// Any response that is not a server error. Enough for a heavy page, where
    /// the point is that bytes arrived rather than which ones.
    Any,
    /// Exactly this status code. Used where a site has a tiny purpose-built
    /// endpoint: `generate_204` answers 204 or nothing at all.
    Status(u16),
    /// This status and this text in the body. Used where a captive portal or a
    /// block page answers 200 with something else entirely.
    Contains(String),
}

/// One URL, and what its answer means.
#[derive(Clone, Debug)]
pub struct Site {
    /// Short name, used in reports and in plan selectors.
    pub name: String,
    pub group: Group,
    pub url: String,
    pub expect: Expect,
}

impl Site {
    pub fn new(name: &str, group: Group, url: &str, expect: Expect) -> Self {
        Self {
            name: name.to_string(),
            group,
            url: url.to_string(),
            expect,
        }
    }
}

/// A set of URLs to ask, in groups.
#[derive(Clone, Debug, Default)]
pub struct Checks {
    sites: Vec<Site>,
}

impl Checks {
    /// The default questions.
    ///
    /// Each URL is a purpose-built endpoint where one exists, because a 40 KB
    /// home page tells us no more than a 0-byte one and costs a second to
    /// download. The markers are what a captive portal or a block page cannot
    /// fake: a portal answers 200 with its own text, and a block answers with
    /// its own page.
    pub fn defaults() -> Self {
        Self {
            sites: vec![
                // alive: one request in each of three unrelated networks, so
                // one unreachable CDN cannot condemn a working node
                Site::new(
                    "gstatic",
                    Group::Alive,
                    "https://www.gstatic.com/generate_204",
                    Expect::Status(204),
                ),
                Site::new(
                    "microsoft",
                    Group::Alive,
                    "https://www.msftconnecttest.com/connecttest.txt",
                    Expect::Contains("Microsoft Connect Test".into()),
                ),
                Site::new(
                    "apple",
                    Group::Alive,
                    "https://captive.apple.com/hotspot-detect.html",
                    Expect::Contains("Success".into()),
                ),
                // ru: reachable from a Russian SIM, which is the whole point of
                // a whitelist-friendly node
                Site::new("vk", Group::RuWorking, "https://vk.com/", Expect::Any),
                Site::new("max", Group::RuWorking, "https://max.ru/", Expect::Any),
                Site::new(
                    "yandex",
                    Group::RuWorking,
                    "https://yandex.ru/",
                    Expect::Any,
                ),
                // unblocks: the reason the node is here
                Site::new(
                    "youtube",
                    Group::Unblocking,
                    "https://www.youtube.com/generate_204",
                    Expect::Status(204),
                ),
                Site::new(
                    "telegram",
                    Group::Unblocking,
                    "https://web.telegram.org/",
                    Expect::Any,
                ),
                Site::new(
                    "whatsapp",
                    Group::Unblocking,
                    "https://web.whatsapp.com/",
                    Expect::Any,
                ),
                // social: every one of these has to answer for the social
                // group. They are checked in parallel and none of them is
                // allowed to short-circuit the others.
                Site::new(
                    "instagram",
                    Group::Social,
                    "https://www.instagram.com/",
                    Expect::Any,
                ),
                Site::new(
                    "whatsapp-com",
                    Group::Social,
                    "https://www.whatsapp.com/",
                    Expect::Any,
                ),
                Site::new("tme", Group::Social, "https://t.me/", Expect::Any),
                Site::new(
                    "telegram-org",
                    Group::Social,
                    "https://telegram.org/",
                    Expect::Any,
                ),
                Site::new("meta", Group::Social, "https://www.meta.com/", Expect::Any),
                Site::new(
                    "tiktok",
                    Group::Social,
                    "https://www.tiktok.com/",
                    Expect::Any,
                ),
                Site::new(
                    "facebook",
                    Group::Social,
                    "https://www.facebook.com/",
                    Expect::Any,
                ),
            ],
        }
    }

    /// Add a URL of one's own, as `name@url` or a bare url.
    ///
    /// Bare urls land in [`Group::Unblocking`], because a URL nobody recognises is
    /// a check someone added on purpose, and the group where it still means
    /// something is the one that decides whether the node stays.
    pub fn with_custom(mut self, group: Option<Group>, spec: &str) -> Checked<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Ok(self);
        }
        // `name@url`, or a bare url that names itself after its host. The first
        // `@` is taken as the separator, which is wrong for a url with
        // credentials in it and right for every url anyone adds by hand.
        let (name, url) = match spec.split_once('@') {
            Some((name, url)) => (name.trim().to_string(), url.trim()),
            None => (String::new(), spec),
        };
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return Err(Error::Probe(format!("not a url: {url}")));
        }
        let group = group.unwrap_or(Group::Unblocking);
        let name = if name.is_empty() { host_of(url) } else { name };
        self.sites.push(Site::new(&name, group, url, Expect::Any));
        Ok(self)
    }

    /// Keep only these groups, in their order.
    ///
    /// For a second look at a node that failed, where the only question worth
    /// asking again is whether it can reach anything blocked: the other eight
    /// requests were already answered the first time.
    pub fn narrow(mut self, groups: &[Group]) -> Self {
        self.sites.retain(|s| groups.contains(&s.group));
        self
    }

    /// Drop a default check by name.
    ///
    /// A site that answers wrongly — a captive portal of its own, a region that
    /// answers a redirect loop — is worse than no check at all, and removing one
    /// is as ordinary as adding a site of your own.
    pub fn disable(&mut self, name: &str) -> Checked<()> {
        let before = self.sites.len();
        self.sites.retain(|s| s.name.to_ascii_lowercase() != name);
        if self.sites.len() == before {
            return Err(Error::Probe(format!("no check named `{name}`")));
        }
        Ok(())
    }

    pub fn sites(&self) -> &[Site] {
        &self.sites
    }

    /// Every site of one group, in declaration order.
    pub fn group(&self, group: Group) -> Vec<&Site> {
        self.sites.iter().filter(|s| s.group == group).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Every distinct name, for reporting.
    pub fn names(&self) -> Vec<&str> {
        self.sites.iter().map(|s| s.name.as_str()).collect()
    }
}

fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("check")
        .trim_start_matches("www.")
        .to_string()
}

/// What one node could reach.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Sites that answered as expected.
    pub passed: Vec<String>,
    /// Sites that did not, with the reason.
    pub failed: Vec<(String, String)>,
    /// Sites never asked, because an earlier one had already settled the node.
    pub skipped: Vec<String>,
}

impl Report {
    /// Did it unblock anything? The question the whole run exists to answer.
    pub fn unblocks(&self, checks: &Checks) -> bool {
        let wanted: Vec<&str> = checks
            .group(Group::Unblocking)
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        wanted.iter().any(|n| self.passed.iter().any(|p| p == n))
    }

    /// Did every site of `group` answer?
    ///
    /// For the social group the question is all-or-nothing, so one passed site
    /// is not a pass. The other groups keep their own any-of semantics.
    pub fn reaches_all(&self, checks: &Checks, group: Group) -> bool {
        let wanted = checks.group(group);
        !wanted.is_empty()
            && wanted
                .iter()
                .all(|site| self.passed.iter().any(|name| name == &site.name))
    }

    /// Does it work from Russia?
    pub fn ru_works(&self, checks: &Checks) -> bool {
        let wanted: Vec<&str> = checks
            .group(Group::RuWorking)
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        wanted.iter().any(|n| self.passed.iter().any(|p| p == n))
    }

    /// `gstatic,youtube`, for a node's `extra` and for the plan selectors.
    pub fn summary(&self) -> String {
        self.passed.join(",")
    }

    /// One line per site, for the verbose mode.
    pub fn lines(&self, checks: &Checks) -> Vec<String> {
        checks
            .sites()
            .iter()
            .map(|site| {
                let verdict = if self.passed.contains(&site.name) {
                    "ok".to_string()
                } else if let Some((_, why)) =
                    self.failed.iter().find(|(name, _)| *name == site.name)
                {
                    why.clone()
                } else {
                    "не проверено".to_string()
                };
                format!("{:<10} {}", site.name, verdict)
            })
            .collect()
    }
}

/// Ask every site through an open SOCKS proxy, cheapest question first.
///
/// Two short-circuits, because a full pass costs a dozen requests and a build
/// runs over hundreds of nodes: a group stops at its first success — each group
/// is a "does it reach *any* of these" question, except `social`, which needs
/// all of them — and the whole set of checks has one time budget, so a node that
/// answers nothing costs a bounded wait.
///
/// No group is skipped because an earlier one failed. That matters more than it
/// sounds: a node with a Russian exit cannot load `gstatic` at all, and skipping
/// the rest on that failure would throw away exactly the whitelist-friendly
/// nodes this subscription exists for, before they were ever asked the question
/// that decides their fate.
pub async fn ask_all(socks: SocketAddr, checks: &Checks, timeout: Duration) -> Report {
    let client = match client_for(socks) {
        Ok(client) => client,
        Err(e) => {
            return Report {
                passed: Vec::new(),
                failed: checks
                    .sites()
                    .iter()
                    .map(|s| (s.name.clone(), e.to_string()))
                    .collect(),
                skipped: Vec::new(),
            }
        }
    };

    // The groups are independent questions, so they are asked at the same time.
    // Sequentially they cost the sum of their worst cases — a node that answers
    // nothing waits the full budget once per group, which is most of the time a
    // run spends.
    let alive = ask_group(&client, checks, Group::Alive, timeout).await;
    let (ru, unblocking, social) = futures::join!(
        ask_group(&client, checks, Group::RuWorking, timeout),
        ask_group(&client, checks, Group::Unblocking, timeout),
        ask_group(&client, checks, Group::Social, timeout),
    );

    let mut report = Report::default();
    report.passed.extend(alive.passed);
    report.passed.extend(ru.passed);
    report.passed.extend(unblocking.passed);
    report.passed.extend(social.passed);
    report.failed.extend(alive.failed);
    report.failed.extend(ru.failed);
    report.failed.extend(unblocking.failed);
    report.failed.extend(social.failed);
    report.skipped.extend(alive.skipped);
    report.skipped.extend(ru.skipped);
    report.skipped.extend(unblocking.skipped);
    report.skipped.extend(social.skipped);

    report
}

/// One group of sites, stopping at its first success.
async fn ask_group(
    client: &reqwest::Client,
    checks: &Checks,
    group: Group,
    timeout: Duration,
) -> Report {
    let mut report = Report::default();
    let sites = checks.group(group);
    if group == Group::Social {
        // All of them, at the same time: the question is "does this node reach
        // every one", so one success must not hide the next failure. Parallel
        // keeps the whole group to one timeout rather than seven.
        let answers = futures::future::join_all(
            sites
                .iter()
                .map(
                    |site| async move { (site.name.clone(), ask_one(client, site, timeout).await) },
                )
                .collect::<Vec<_>>(),
        )
        .await;
        for (name, answer) in answers {
            match answer {
                Ok(()) => report.passed.push(name),
                Err(e) => report.failed.push((name, e)),
            }
        }
        return report;
    }
    for (i, site) in sites.iter().enumerate() {
        if !report.passed.is_empty() {
            // One answer settles the group: each of them is a "does it reach
            // *any* of these" question. A failure does not — the networks in
            // `alive` are independent, and a node that cannot load a Microsoft
            // captive-portal page can still load YouTube perfectly.
            report
                .skipped
                .extend(sites[i + 1..].iter().map(|s| s.name.clone()));
            break;
        }
        // The whole node is capped: a node that answers nothing costs a bounded
        // wait rather than one timeout per url.
        if i as u32 * timeout >= timeout * 3 {
            report
                .skipped
                .extend(sites[i..].iter().map(|s| s.name.clone()));
            break;
        }
        match ask_one(client, site, timeout).await {
            Ok(()) => report.passed.push(site.name.clone()),
            Err(e) => report.failed.push((site.name.clone(), e)),
        }
    }
    report
}

async fn ask_one(
    client: &reqwest::Client,
    site: &Site,
    timeout: Duration,
) -> std::result::Result<(), String> {
    // HEAD on a full page: what matters is that the response arrived through the
    // tunnel, and a body we were never going to read is pure latency.
    let send = match &site.expect {
        Expect::Contains(_) => client.get(&site.url).send(),
        _ => client.head(&site.url).send(),
    };
    let response = tokio::time::timeout(timeout, send)
        .await
        .map_err(|_| format!("{timeout:?} без ответа"))?
        .map_err(|e| tail(&e.to_string()))?;

    let status = response.status();
    match &site.expect {
        Expect::Any => {
            if status.is_server_error() {
                Err(format!("http {}", status.as_u16()))
            } else {
                Ok(())
            }
        }
        Expect::Status(want) => {
            if status.as_u16() == *want {
                Ok(())
            } else {
                Err(format!("http {}", status.as_u16()))
            }
        }
        Expect::Contains(needle) => {
            let body = match tokio::time::timeout(timeout, response.text()).await {
                Ok(Ok(body)) => body,
                Ok(Err(e)) => return Err(tail(&e.to_string())),
                Err(_) => return Err("тело не пришло".into()),
            };
            if body.contains(needle.as_str()) {
                Ok(())
            } else {
                Err(format!("нет маркера {}", truncate(needle, 24)))
            }
        }
    }
}

fn client_for(socks: SocketAddr) -> Checked<reqwest::Client> {
    reqwest::Client::builder()
        // socks5h: the far end resolves the name, or we would be measuring the
        // local network's idea of where youtube is.
        .proxy(
            reqwest::Proxy::all(format!("socks5h://{socks}"))
                .map_err(|e| Error::Probe(e.to_string()))?,
        )
        .user_agent("v2keylib/0.1")
        // Redirects are followed by default; some of these sites answer 301 to a
        // localised URL, and a 301 is a working node, not a broken one.
        .build()
        .map_err(|e| Error::Probe(e.to_string()))
}

/// The end of an error message: the middle of a reqwest failure is a stack of
/// socket bookkeeping that says nothing about the node.
fn tail(text: &str) -> String {
    let end = match text.rsplit_once(": ") {
        Some((_, end)) if end.len() < 70 => end.to_string(),
        _ => text
            .rsplit_once(' ')
            .map(|(_, e)| e)
            .unwrap_or(text)
            .to_string(),
    };
    let mut out: String = end.chars().take(48).collect();
    if end.chars().count() > 48 {
        out.push('…');
    }
    out
}

fn truncate(text: &str, limit: usize) -> String {
    let mut out: String = text.chars().take(limit).collect();
    if text.chars().count() > limit {
        out.push('…');
    }
    out
}

use crate::error::Error;
use crate::error::Result as Checked;
