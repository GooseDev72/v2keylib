//! One type for every geo source, with format sniffing on load.
//!
//! ```no_run
//! use v2keylib::geo::GeoDb;
//!
//! // XRay geoip.dat, MaxMind .mmdb — the format is detected from the content,
//! // not from the file name, so `geoip.dat` that is really a MaxMind DB still
//! // loads (and the reverse).
//! let db = GeoDb::load("geoip.dat")?;
//! println!("{}", db.kind());
//!
//! // or a remote IP-API
//! let remote = GeoDb::remote(v2keylib::geo::api::Provider::IpApiCom)?;
//!
//! // one cascade entry point for either; only the network use differs
//! let rt = tokio::runtime::Runtime::new()?;
//! let report = rt.block_on(db.cascade(&std::fs::read_to_string("sub.json")?, Some("RU"), 8))?;
//! println!("{}", report.summary_line());
//! # let _ = remote;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::IpAddr;
use std::path::Path;

use crate::error::{Error, Result};
use crate::geo::api::{IpApiResolver, Provider};
use crate::geo::cascade::{self, CascadeReport};
use crate::geo::mmdb::CountryDb;
use crate::geo::xray_dat::GeoIpDat;
use crate::geo::{GeoInfo, GeoResolver};

/// The marker every MaxMind database carries in its metadata section.
const MAXMIND_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

/// Where country data comes from.
pub enum GeoDb {
    /// XRay `geoip.dat` (protobuf), e.g. `runetfreedom/russia-v2ray-rules-dat`.
    XrayDat(GeoIpDat),
    /// MaxMind `.mmdb` (GeoLite2-Country / GeoIP2-Country).
    Mmdb(CountryDb),
    /// Remote IP-API.
    Remote(IpApiResolver),
}

impl std::fmt::Debug for GeoDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
    }
}

impl GeoDb {
    /// Load a local database, detecting the format from its contents.
    ///
    /// The file name is deliberately ignored: providers ship `geoip.dat`,
    /// `GeoLite2-Country.mmdb` and plenty of mislabelled copies, and guessing
    /// from the extension is how you end up with "empty" country lookups.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        Self::load_bytes(&bytes)
            .map_err(|e| Error::GeoIp(format!("{}: {e}", path.display())))
    }

    /// Same, from memory.
    pub fn load_bytes(bytes: &[u8]) -> Result<Self> {
        let result = Self::sniff(bytes);
        result.map_err(|e| {
            Error::GeoIp(format!(
                "{e} (looked for MaxMind .mmdb and XRay geoip.dat)"
            ))
        })
    }

    fn sniff(bytes: &[u8]) -> Result<Self> {
        if is_maxmind(bytes) {
            let path = std::env::temp_dir().join(format!(
                "v2keylib-mmdb-{}-{:p}.mmdb",
                std::process::id(),
                bytes
            ));
            std::fs::write(&path, bytes)?;
            let db = CountryDb::open(&path);
            let _ = std::fs::remove_file(&path);
            return Ok(GeoDb::Mmdb(db?));
        }
        Ok(GeoDb::XrayDat(GeoIpDat::parse(bytes)?))
    }

    /// A remote IP-API source.
    pub fn remote(provider: Provider) -> Result<Self> {
        Ok(GeoDb::Remote(IpApiResolver::new(provider)?))
    }

    /// Short name of the source, for logs and CLI output.
    pub fn kind(&self) -> &'static str {
        match self {
            GeoDb::XrayDat(_) => "geoip.dat (XRay protobuf)",
            GeoDb::Mmdb(_) => "MaxMind .mmdb",
            GeoDb::Remote(r) => match r.provider() {
                Provider::IpApiCom => "ip-api.com",
                Provider::IpWhoIs => "ipwho.is",
                Provider::IpApiCo => "ipapi.co",
            },
        }
    }

    pub fn is_remote(&self) -> bool {
        matches!(self, GeoDb::Remote(_))
    }

    /// Local resolvers only: `None` for a remote source.
    pub fn as_local(&self) -> Option<&dyn GeoResolver> {
        match self {
            GeoDb::XrayDat(db) => Some(db),
            GeoDb::Mmdb(db) => Some(db),
            GeoDb::Remote(_) => None,
        }
    }

    /// Countries for a batch of IPs.
    ///
    /// Local sources resolve synchronously; a remote source makes one request
    /// per distinct IP, bounded by `concurrency` and cached afterwards.
    pub async fn resolve_many(&self, ips: &[IpAddr], concurrency: usize) -> Vec<(IpAddr, Option<GeoInfo>)> {
        match self {
            GeoDb::Remote(api) => api.lookup_many(ips, concurrency).await,
            other => {
                let resolver = other.as_local().expect("local source");
                ips.iter()
                    .map(|ip| (*ip, resolver.resolve_ip(*ip).ok().flatten()))
                    .collect()
            }
        }
    }

    /// Cascade over a config of any supported shape.
    pub async fn cascade(
        &self,
        body: &str,
        entry_country: Option<&str>,
        concurrency: usize,
    ) -> Result<CascadeReport> {
        if let GeoDb::Remote(api) = self {
            return cascade::cascade_from_config_api(body, api, entry_country, concurrency).await;
        }
        // local: resolve hostnames first, a local database cannot look those up
        let mut nodes = crate::subscription::parse_body(body)?.nodes();
        cascade::resolve_addresses(&mut nodes, concurrency).await;
        Ok(cascade::cascade_report(&nodes, self.as_local().expect("local source"), entry_country))
    }

    /// Offline variant: refuses a remote source instead of silently ignoring it.
    pub fn cascade_offline(
        &self,
        body: &str,
        entry_country: Option<&str>,
    ) -> Result<CascadeReport> {
        let resolver = self.as_local().ok_or_else(|| {
            Error::GeoIp("this source needs network; use cascade()".into())
        })?;
        cascade::cascade_from_config(body, resolver, entry_country)
    }

    /// The entry country for this machine, via a remote echo service.
    pub async fn entry_country(&self) -> Result<Option<String>> {
        match self {
            GeoDb::Remote(api) => api.entry_country().await,
            other => {
                let ip = self.local_ip().await?;
                Ok(other.as_local().and_then(|r| r.country_of(ip)))
            }
        }
    }

    /// This machine's public IP, via `ECHO_SERVICES`.
    pub async fn local_ip(&self) -> Result<IpAddr> {
        match self {
            GeoDb::Remote(api) => api.local_ip().await,
            _ => crate::geo::api::local_ip(&reqwest::Client::new()).await,
        }
    }
}

fn is_maxmind(bytes: &[u8]) -> bool {
    // The marker sits in the metadata section, which MaxMind places at the *end*
    // of the file — a GeoLite2-Country DB has it around 8 MB in. Scanning only a
    // prefix silently misdetects every real .mmdb, so the whole file is scanned
    // (a linear scan of a few MB is microseconds).
    bytes.windows(MAXMIND_MARKER.len()).any(|w| w == MAXMIND_MARKER)
}

impl GeoDb {
    /// A geoip.dat group name that is not an ISO country code.
    pub fn is_category(code: &str) -> bool {
        crate::geo::xray_dat::is_category(code)
    }
}