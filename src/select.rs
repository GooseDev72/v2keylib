//! Choosing configs by number: `"1-5,8,10-12"`.
//!
//! This is the input language of the balancer constructor and of any CLI that
//! needs to turn a printed list into a subset.

use crate::error::{Error, Result};

/// Parse a 1-based selection into 0-based indices, sorted and deduplicated.
///
/// Accepts `N`, `N-M` (both bounds inclusive, either may be omitted for an
/// open range) and any mixture separated by commas or spaces:
///
/// ```
/// use v2keylib::select::parse_selection;
/// assert_eq!(parse_selection("1-3,7", 10).unwrap(), vec![0, 1, 2, 6]);
/// assert_eq!(parse_selection("-4", 10).unwrap(), vec![0, 1, 2, 3], "open start");
/// assert_eq!(parse_selection("8-", 10).unwrap(), vec![7, 8, 9], "open end");
/// assert_eq!(parse_selection("all", 3).unwrap(), vec![0, 1, 2]);
/// ```
///
/// A reversed or out-of-range selection is a typo, and silently repairing it
/// would hand the caller a group they did not ask for, so it is rejected:
///
/// ```
/// use v2keylib::select::parse_selection;
/// assert!(parse_selection("3-1", 10).is_err());
/// assert!(parse_selection("99", 10).is_err());
/// assert!(parse_selection("0", 10).is_err());
/// ```
pub fn parse_selection(input: &str, len: usize) -> Result<Vec<usize>> {
    let text = input.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.eq_ignore_ascii_case("all") || text == "*" || text == ":" {
        return Ok((0..len).collect());
    }

    let mut out = Vec::new();
    for part in text.split([',', ' ', ';']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.extend(parse_part(part, len)?);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn parse_part(part: &str, len: usize) -> Result<Vec<usize>> {
    let bad = |why: &str| -> Error {
        Error::MalformedLink(format!(
            "bad selection {part:?}: {why} (list has {len} entries)"
        ))
    };

    let (from, to) = match part.split_once('-') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (part, part),
    };

    // "-" alone means "everything"
    if from.is_empty() && to.is_empty() {
        return Ok((0..len).collect());
    }

    let start = if from.is_empty() {
        1
    } else {
        parse_num(from).ok_or_else(|| bad("expected a number"))?
    };
    let end = if to.is_empty() {
        len
    } else {
        parse_num(to).ok_or_else(|| bad("expected a number"))?
    };
    if start < 1 || end < 1 {
        return Err(bad("numbers are 1-based"));
    }
    if start > len || end > len {
        return Err(bad("number out of range"));
    }
    if start > end {
        return Err(bad("range is reversed"));
    }
    Ok((start - 1..end).collect())
}

fn parse_num(raw: &str) -> Option<usize> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, '#' | '\u{2116}' | '.' | ','))
        .collect();
    cleaned.parse().ok().or_else(|| cleaned.parse().ok())
}

/// Renumber a list after filtering: `keep = [2,5,7]` -> new positions of those
/// entries, so a constructor can print a sub-list and map back.
/// Format a numeric range compactly: `[1,2,3,7,9,10]` -> `"1-3,7,9-10"`.
pub fn format_range(indices: &[usize]) -> String {
    let mut sorted: Vec<usize> = indices.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut parts = Vec::new();
    let mut start: Option<usize> = None;
    let mut prev: Option<usize> = None;
    for i in sorted {
        match (start, prev) {
            (Some(_), Some(p)) if i == p + 1 => prev = Some(i),
            (Some(s), Some(p)) => {
                parts.push(if s == p { format!("{}", s + 1) } else { format!("{}-{}", s + 1, p + 1) });
                start = Some(i);
                prev = Some(i);
            }
            _ => {
                start = Some(i);
                prev = Some(i);
            }
        }
    }
    if let (Some(s), Some(p)) = (start, prev) {
        parts.push(if s == p { format!("{}", s + 1) } else { format!("{}-{}", s + 1, p + 1) });
    }
    parts.join(",")
}
