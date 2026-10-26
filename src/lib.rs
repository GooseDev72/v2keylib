//! # v2keylib
//!
//! A toolkit for professional work with V2Ray / XRay / v2fly keys: parse and
//! render proxy links and full client configs, build and decompose balancers,
//! filter by IP/CIDR and country, and probe nodes for liveness.
//!
//! ## Quick start
//!
//! Convert a subscription into every format:
//!
//! ```no_run
//! use v2keylib::config::{BalancerKind, BalancerSpec, Format};
//! use v2keylib::pipeline::{Output, Pipeline};
//! # async fn run() -> v2keylib::error::Result<()> {
//! let outputs = Pipeline::new()
//!     .input(v2keylib::pipeline::Input::Url(
//!         "https://example.com/subscription".into(),
//!     ))
//!     .dedup(true)
//!     .output(Output::Links)
//!     .output(Output::balanced(Format::XrayJson, "auto", BalancerKind::UrlTest))
//!     .output(Output::balanced(Format::MihomoYaml, "auto", BalancerKind::UrlTest))
//!     .run()
//!     .await?;
//! # let _ = outputs;
//! # Ok(()) }
//! ```
//!
//! Work with a single link directly:
//!
//! ```
//! use v2keylib::{config::Format, links};
//!
//! let node = links::parse("vless://uuid@example.com:443?security=reality&type=ws&sni=cdn.example.com&path=/ws").unwrap();
//! assert_eq!(node.address, "example.com");
//! let json = v2keylib::config::render(Format::XrayJson, &[node], None).unwrap();
//! assert!(json.contains("realitySettings"));
//! ```
//!
//! Decompose a balancer-only subscription back into plain links:
//!
//! ```
//! let cfg = std::fs::read_to_string("tests/fixtures/xray_balancer.json").unwrap();
//! let bundle = v2keylib::config::parse(&cfg).unwrap();
//! let links = v2keylib::balancer::decompose(&bundle).unwrap();
//! assert_eq!(links.lines().count(), 3);
//! ```

pub mod balancer;
pub mod checks;
pub mod config;
pub mod error;
pub mod filter;
pub mod geo;
pub mod links;
pub mod node;
pub mod pipeline;
pub mod probe;
pub mod publish;
#[cfg(feature = "python")]
mod python;

pub mod select;
pub mod subscription;
pub mod tunnel;
pub mod util;

pub use error::{Error, Result};
pub use node::{Node, Protocol, Security, Transport, TransportKind};
