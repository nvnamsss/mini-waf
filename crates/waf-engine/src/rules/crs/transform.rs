//! Input transformations applied before operator matching.
//!
//! The most common PL1 chain is: `t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls`.

use std::borrow::Cow;
use std::sync::OnceLock;
use regex::Regex;
use crate::rules::crs::types::CrsTransform;

/// Apply each transform in sequence and return the result.
///
/// Returns `Cow::Borrowed(s)` — with zero allocations — when no transform
/// modifies the input (common for clean ASCII request fields).
pub fn apply_transforms<'a>(s: &'a str, transforms: &[CrsTransform]) -> Cow<'a, str> {
    let mut result: Cow<'a, str> = Cow::Borrowed(s);
    for t in transforms {
        result = match t {
            // ── true no-ops in a Rust UTF-8 world ────────────────────────
            CrsTransform::Utf8ToUnicode => result,
            CrsTransform::CssDecode    => result,

            // ── cheap fast-path: borrow when the transform changes nothing ─
            CrsTransform::RemoveNulls => {
                if !result.contains('\0') { result }
                else { Cow::Owned(result.replace('\0', "")) }
            }
            CrsTransform::Trim => {
                let trimmed = result.trim();
                if trimmed.len() == result.len() { result }
                else { Cow::Owned(trimmed.to_owned()) }
            }
            CrsTransform::Lowercase => {
                // Fast ASCII check: only allocate if any byte is A-Z.
                if result.bytes().all(|b| !b.is_ascii_uppercase()) { result }
                else { Cow::Owned(result.to_lowercase()) }
            }
            CrsTransform::UrlDecodeUni => {
                // Most clean inputs have no '%'; skip the scan+alloc.
                if !result.contains('%') { result }
                else { Cow::Owned(url_decode_uni(&result)) }
            }
            CrsTransform::HtmlEntityDecode => {
                if !result.contains('&') { result }
                else { Cow::Owned(html_entity_decode(&result)) }
            }
            CrsTransform::ReplaceComments => {
                if !result.contains("/*") && !result.contains("--") { result }
                else { Cow::Owned(replace_comments(&result)) }
            }

            // ── always-allocate (scan cost ≈ transform cost) ───────────────
            CrsTransform::CompressWhitespace => Cow::Owned(compress_whitespace(&result)),
            CrsTransform::NormalizePath      => Cow::Owned(normalize_path(&result)),
            CrsTransform::JsDecode           => Cow::Owned(js_decode(&result)),
            CrsTransform::Base64Decode       => Cow::Owned(base64_decode(&result)),
            CrsTransform::RemoveWhitespace   => {
                Cow::Owned(result.chars().filter(|c| !c.is_whitespace()).collect())
            }
            CrsTransform::Length => Cow::Owned(result.chars().count().to_string()),
            CrsTransform::EscapeSeqDecode => Cow::Owned(escape_seq_decode(&result)),
        };
    }
    result
}

// ─── URL decoding ────────────────────────────────────────────────────────────

/// Percent-decode (`%XX`).  `+` is left as-is.
pub fn url_decode_uni(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ─── Escape sequence decode ──────────────────────────────────────────────────

/// Decode C-style backslash escape sequences, matching ModSecurity `escapeSeqDecode`:
/// `\n`, `\r`, `\t`, `\xHH`, `\uHHHH`.  Unknown escapes are passed through unchanged.
fn escape_seq_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'n'  => { out.push(b'\n'); i += 2; }
                b'r'  => { out.push(b'\r'); i += 2; }
                b't'  => { out.push(b'\t'); i += 2; }
                b'x' if i + 3 < b.len() => {
                    if let (Some(h), Some(l)) = (hex(b[i + 2]), hex(b[i + 3])) {
                        out.push((h << 4) | l);
                        i += 4;
                    } else {
                        out.push(b[i]); i += 1;
                    }
                }
                b'u' if i + 5 < b.len() => {
                    let nibbles = [b[i+2], b[i+3], b[i+4], b[i+5]];
                    if let (Some(h1), Some(h2), Some(l1), Some(l2)) =
                        (hex(nibbles[0]), hex(nibbles[1]), hex(nibbles[2]), hex(nibbles[3]))
                    {
                        let cp = ((h1 as u32) << 12) | ((h2 as u32) << 8)
                               | ((l1 as u32) << 4) | (l2 as u32);
                        if let Some(c) = char::from_u32(cp) {
                            let mut buf = [0u8; 4];
                            let encoded = c.encode_utf8(&mut buf);
                            out.extend_from_slice(encoded.as_bytes());
                            i += 6;
                        } else {
                            out.push(b[i]); i += 1;
                        }
                    } else {
                        out.push(b[i]); i += 1;
                    }
                }
                _ => { out.push(b[i]); i += 1; }
            }
        } else {
            out.push(b[i]); i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ─── Whitespace ──────────────────────────────────────────────────────────────

static WS_RE: OnceLock<Regex> = OnceLock::new();
fn ws_re() -> &'static Regex {
    WS_RE.get_or_init(|| Regex::new(r"\s+").unwrap())
}

fn compress_whitespace(s: &str) -> String {
    ws_re().replace_all(s, " ").into_owned()
}

// ─── Path normalisation ───────────────────────────────────────────────────────

fn normalize_path(s: &str) -> String {
    // Decode then collapse ../ sequences.
    let s = url_decode_uni(s);
    let s = s.replace("../", "/").replace("..\\", "\\");
    // Collapse double slashes.
    let mut out = s.clone();
    while out.contains("//") { out = out.replace("//", "/"); }
    out
}

// ─── HTML entity decode ───────────────────────────────────────────────────────

fn html_entity_decode(s: &str) -> String {
    s.replace("&lt;",   "<")
     .replace("&gt;",   ">")
     .replace("&amp;",  "&")
     .replace("&quot;", "\"")
     .replace("&#x27;", "'")
     .replace("&#39;",  "'")
     .replace("&apos;", "'")
     .replace("&#x3C;", "<")
     .replace("&#x3E;", ">")
     .replace("&nbsp;", " ")
}

// ─── JS decode ───────────────────────────────────────────────────────────────

fn js_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'x' if i + 3 < bytes.len() => {
                    if let (Some(h), Some(l)) = (hex(bytes[i + 2]), hex(bytes[i + 3])) {
                        out.push(((h << 4) | l) as char);
                        i += 4;
                        continue;
                    }
                }
                b'u' if i + 5 < bytes.len() => {
                    let code = (0..4_usize).try_fold(0u16, |acc, j| {
                        hex(bytes[i + 2 + j]).map(|v| (acc << 4) | v as u16)
                    });
                    if let Some(c) = code.and_then(|n| char::from_u32(n as u32)) {
                        out.push(c);
                        i += 6;
                        continue;
                    }
                }
                b'n' => { out.push('\n'); i += 2; continue; }
                b'r' => { out.push('\r'); i += 2; continue; }
                b't' => { out.push('\t'); i += 2; continue; }
                _ => {}
            }
        }
        // Safe for WAF purposes: non-ASCII bytes treated as Latin-1 code points.
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

// ─── Base64 decode ───────────────────────────────────────────────────────────

fn base64_decode(s: &str) -> String {
    const INVALID: i8 = -1;
    let mut table = [INVALID; 256_usize];
    for (i, &c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[c as usize] = i as i8;
    }

    let clean: Vec<u8> = s.bytes().filter(|&b| table[b as usize] >= 0 || b == b'=').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < clean.len() {
        let (a, b, c, d) = (
            table[clean[i] as usize],
            table[clean[i + 1] as usize],
            table[clean[i + 2] as usize],
            table[clean[i + 3] as usize],
        );
        if a < 0 || b < 0 { break; }
        let (a, b) = (a as u8, b as u8);
        out.push((a << 2) | ((b & 0x30) >> 4));
        if c >= 0 {
            let c = c as u8;
            out.push(((b & 0x0f) << 4) | ((c & 0x3c) >> 2));
            if d >= 0 {
                let d = d as u8;
                out.push(((c & 0x03) << 6) | d);
            }
        }
        i += 4;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ─── Comment replacement ─────────────────────────────────────────────────────

fn replace_comments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            // Scan for closing */
            let rest = &bytes[i + 2..];
            if let Some(end) = rest.windows(2).position(|w| w == b"*/") {
                i += 2 + end + 2;
            } else {
                i = bytes.len();
            }
        } else if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            while i < bytes.len() && bytes[i] != b'\n' { i += 1; }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}
