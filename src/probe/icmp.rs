//! ICMP echo without raw-socket privileges: Linux `ping` and BSD/macOS ping.
//!
//! `-W` is seconds on Linux (iputils) but milliseconds on some BSD builds, so
//! the whole command is additionally wrapped in a hard timeout — a wrong unit
//! must never turn into an unbounded wait.

use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::process::Command;

use crate::error::{Error, Result};
use crate::node::Node;

/// Run an ICMP echo against the node address and return the round trip time.
///
/// Uses the system `ping`, which on Linux uses datagram ICMP sockets, so no
/// `CAP_NET_RAW` is required.
pub async fn icmp_probe(node: &Node, timeout: Duration) -> Result<Duration> {
    let addr = node.address.clone();
    let secs = timeout.as_secs().clamp(1, 60);
    let start = Instant::now();

    #[cfg(windows)]
    let attempts: Vec<Vec<String>> = vec![
        vec!["-n".into(), "1".into(), "-w".into(), secs.to_string(), addr.clone()],
        vec![addr.clone()],
    ];
    #[cfg(not(windows))]
    let attempts: Vec<Vec<String>> = vec![
        vec![
            "-n".into(),
            "-q".into(),
            "-c".into(),
            "1".into(),
            "-W".into(),
            secs.to_string(),
            addr.clone(),
        ],
        vec!["-n".into(), "-c".into(), "1".into(), addr.clone()],
        vec!["-c".into(), "1".into(), addr.clone()],
    ];

    let mut last_err = format!("ping is not available for {addr}");
    for args in attempts {
        let mut cmd = Command::new("ping");
        cmd.args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let hard_deadline = timeout.saturating_mul(2).max(Duration::from_secs(5));
        let outcome = tokio::time::timeout(hard_deadline, cmd.output()).await;

        let output = match outcome {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                last_err = e.to_string();
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Err(Error::Probe(format!("icmp {addr}: ping binary not found")));
                }
                continue;
            }
            Err(_) => {
                last_err = format!("ping did not exit within {hard_deadline:?}");
                continue;
            }
        };

        if output.status.success() {
            return Ok(start.elapsed());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        last_err = if stderr.trim().is_empty() {
            match output.status.code() {
                Some(1) => "no reply".to_string(),
                Some(2) => "bad arguments".to_string(),
                other => format!("ping exited with {other:?}"),
            }
        } else {
            stderr.trim().to_string()
        };
        // Unsupported flags mean this is a different ping dialect: retry.
        if last_err.contains("unknown option")
            || last_err.contains("bad option")
            || last_err.contains("invalid option")
            || last_err.contains("usage:")
        {
            continue;
        }
        break;
    }

    Err(Error::Probe(format!("icmp {addr}: {last_err}")))
}
