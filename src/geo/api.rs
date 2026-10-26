//! Remote country lookup via a free IP-API (ip-api.com, ipwho.is, ipapi.co).
//!
//! Used when no local MMDB is available. Batch-friendly and rate-limited, so
//! results are cached per IP for the lifetime of the resolver.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::geo::GeoInfo;

/// Which provider to talk to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    IpApiCom,
    IpWhoIs,
    IpApiCo,
}

impl Provider {
    #[allow(clippy::should_implement_trait)]
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ip-api.com" | "ip-api" => Ok(Provider::IpApiCom),
            "ipwho.is" | "ipwhois" => Ok(Provider::IpWhoIs),
            "ipapi.co" | "ipapico" => Ok(Provider::IpApiCo),
            other => Err(Error::GeoApi(format!("unknown provider: {other}"))),
        }
    }

    /// Request URL for a single-IP lookup.
    pub fn url(self, ip: IpAddr) -> String {
        match self {
            Provider::IpApiCom => format!(
                "http://ip-api.com/json/{ip}?fields=status,message,countryCode,country,regionName,city,query,proxy,hosting"
            ),
            Provider::IpWhoIs => format!("https://ipwho.is/{ip}"),
            Provider::IpApiCo => format!("https://ipapi.co/{ip}/json/"),
        }
    }
}

#[derive(Deserialize)]
struct IpApiCom {
    #[serde(default)]
    status: Option<String>,
    message: Option<String>,
    country_code: Option<String>,
    #[serde(rename = "countryCode")]
    country_code_alt: Option<String>,
    #[serde(rename = "proxy")]
    proxy: Option<bool>,
    hosting: Option<bool>,
    city: Option<String>,
}

#[derive(Deserialize)]
struct IpWhoIs {
    success: Option<bool>,
    country_code: Option<String>,
    city: Option<String>,
    connection: Option<Connection>,
}

#[derive(Deserialize)]
struct Connection {
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Deserialize)]
struct IpApiCo {
    country_iso: Option<String>,
    city: Option<String>,
}

pub struct IpApiResolver {
    provider: Provider,
    client: reqwest::Client,
    cache: Mutex<std::collections::HashMap<IpAddr, Option<GeoInfo>>>,
}

impl IpApiResolver {
    /// Which service this resolver talks to.
    pub fn provider(&self) -> Provider {
        self.provider
    }

    pub fn new(provider: Provider) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("v2keylib/0.1")
            .build()
            .map_err(|e| Error::GeoApi(e.to_string()))?;
        Ok(Self {
            provider,
            client,
            cache: Mutex::new(std::collections::HashMap::new()),
        })
    }

    pub fn default_provider() -> Result<Self> {
        Self::new(Provider::IpApiCom)
    }

    pub async fn lookup(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        if let Some(hit) = self.cache.lock().unwrap().get(&ip) {
            return Ok(hit.clone());
        }
        let info = self.fetch(ip).await?;
        self.cache.lock().unwrap().insert(ip, info.clone());
        Ok(info)
    }

    async fn fetch(&self, ip: IpAddr) -> Result<Option<GeoInfo>> {
        let text = self
            .client
            .get(self.provider.url(ip))
            .send()
            .await
            .map_err(|e| Error::GeoApi(e.to_string()))?
            .text()
            .await
            .map_err(|e| Error::GeoApi(e.to_string()))?;

        let info = match self.provider {
            Provider::IpApiCom => {
                let v: IpApiCom = serde_json::from_str(&text)
                    .map_err(|e| Error::GeoApi(format!("{e}: {text}")))?;
                if v.status.as_deref() != Some("success") {
                    return Err(Error::GeoApi(
                        v.message.unwrap_or_else(|| "lookup failed".into()),
                    ));
                }
                Some(GeoInfo {
                    ip,
                    country: v.country_code_alt.or(v.country_code),
                    city: v.city,
                    anycast: v.proxy.unwrap_or(false) || v.hosting.unwrap_or(false),
                })
            }
            Provider::IpWhoIs => {
                let v: IpWhoIs = serde_json::from_str(&text)
                    .map_err(|e| Error::GeoApi(format!("{e}: {text}")))?;
                if v.success == Some(false) {
                    return Ok(None);
                }
                Some(GeoInfo {
                    ip,
                    country: v.country_code,
                    city: v.city,
                    anycast: v
                        .connection
                        .and_then(|c| c.isp)
                        .map(|isp| {
                            let isp = isp.to_ascii_lowercase();
                            isp.contains("cloudflare")
                                || isp.contains("akamai")
                                || isp.contains("amazon")
                                || isp.contains("google")
                                || isp.contains("microsoft")
                        })
                        .unwrap_or(false),
                })
            }
            Provider::IpApiCo => {
                let v: IpApiCo = serde_json::from_str(&text)
                    .map_err(|e| Error::GeoApi(format!("{e}: {text}")))?;
                Some(GeoInfo {
                    ip,
                    country: v.country_iso,
                    city: v.city,
                    anycast: false,
                })
            }
        };
        Ok(info)
    }

    /// This machine's own public IP, via an external echo service.
    pub async fn local_ip(&self) -> Result<IpAddr> {
        local_ip(&self.client).await
    }

    /// The entry country of this machine: own public IP, then a lookup.
    ///
    /// Handy as the entry side of a cascade when the exit side is resolved from
    /// a local database, or the other way round.
    pub async fn entry_country(&self) -> Result<Option<String>> {
        let ip = self.local_ip().await?;
        Ok(self.lookup(ip).await?.and_then(|i| i.country))
    }

    /// Resolve many IPs concurrently (bounded by `concurrency`).
    pub async fn lookup_many(
        &self,
        ips: &[IpAddr],
        concurrency: usize,
    ) -> Vec<(IpAddr, Option<GeoInfo>)> {
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        use futures::StreamExt;
        futures::stream::iter(ips.iter().copied().map(|ip| {
            let sem = sem.clone();
            async move {
                let permit = match sem.acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => return (ip, None),
                };
                let res = self.lookup(ip).await.ok().flatten();
                drop(permit);
                (ip, res)
            }
        }))
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await
    }
}

/// Public-IP echo services, tried in order.
///
/// Any single one of them can be unreachable (blocked, rate limited, DNS
/// filtered), and the entry side of a cascade is useless without it, so a
/// failure falls through to the next rather than aborting.
pub const ECHO_SERVICES: &[&str] = &[
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://api4.myip.com",
    "https://ident.me",
];

/// The machine's own public IP (entry side of a cascade).
pub async fn local_ip(client: &reqwest::Client) -> Result<std::net::IpAddr> {
    let mut last = String::from("no echo service tried");
    for url in ECHO_SERVICES {
        let text = match client.get(*url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(text) => text,
                Err(e) => {
                    last = format!("{url}: {e}");
                    continue;
                }
            },
            Ok(resp) => {
                last = format!("{url}: http {}", resp.status().as_u16());
                continue;
            }
            Err(e) => {
                last = format!("{url}: {e}");
                continue;
            }
        };
        let candidate = text.trim();
        if let Ok(ip) = candidate.parse::<std::net::IpAddr>() {
            return Ok(ip);
        }
        last = format!("{url}: not an ip: {candidate:?}");
    }
    Err(Error::GeoApi(format!(
        "could not determine the public IP (last: {last})"
    )))
}
