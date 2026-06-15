//! Extract string values for CRS target variables from a `RequestContext`.

use crate::context::RequestContext;
use crate::rules::crs::types::CrsTarget;
use crate::rules::crs::tx::TxState;

/// Return all string values for `target` given the current request and TX state.
pub fn extract_values(target: &CrsTarget, ctx: &RequestContext, tx: &TxState) -> Vec<String> {
    match target {
        CrsTarget::Args => {
            let mut vals = form_values(ctx.query.as_deref().unwrap_or(""));
            if let Some(body) = &ctx.body {
                if is_form_body(ctx) {
                    if let Ok(s) = std::str::from_utf8(body) {
                        vals.extend(form_values(s));
                    }
                }
            }
            vals
        }

        CrsTarget::ArgsNames => {
            let mut names = form_names(ctx.query.as_deref().unwrap_or(""));
            if let Some(body) = &ctx.body {
                if is_form_body(ctx) {
                    if let Ok(s) = std::str::from_utf8(body) {
                        names.extend(form_names(s));
                    }
                }
            }
            names
        }

        CrsTarget::RequestCookies      => cookie_values(ctx),
        CrsTarget::RequestCookiesNames => cookie_names(ctx),

        CrsTarget::RequestHeaders(None) => ctx.headers.values().cloned().collect(),
        CrsTarget::RequestHeaders(Some(name)) => {
            let key = name.to_lowercase();
            ctx.headers.iter()
                .filter(|(k, _)| k.to_lowercase() == key)
                .map(|(_, v)| v.clone())
                .collect()
        }

        CrsTarget::RequestUri | CrsTarget::RequestUriRaw => vec![build_uri(ctx)],

        CrsTarget::RequestFilename => vec![ctx.path.clone()],
        CrsTarget::RequestBasename => vec![
            ctx.path.rsplit('/').next().unwrap_or("").to_owned()
        ],

        CrsTarget::RequestMethod => vec![ctx.method.clone()],
        CrsTarget::RequestBody => vec![
            ctx.body.as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default()
        ],
        CrsTarget::RequestLine => {
            vec![format!("{} {} HTTP/1.1", ctx.method, build_uri(ctx))]
        }

        CrsTarget::QueryString => {
            vec![ctx.query.clone().unwrap_or_default()]
        }

        CrsTarget::RemoteAddr => vec![ctx.client_ip.clone()],

        CrsTarget::Tx(var) => {
            // TX:/regex/ is a "collection reference" — matches all TX variables
            // whose names match the pattern.  We don't track collection vars
            // (multipart headers, param counters, etc.), so always return empty.
            if var.starts_with('/') { return vec![]; }
            vec![tx.get(var).to_string()]
        }
        CrsTarget::TxCount(var) => {
            // &TX:VAR — 1 if the variable is set and non-zero, else 0.
            vec![(if tx.get(var) != 0 { 1i64 } else { 0 }).to_string()]
        }
        CrsTarget::RequestHeadersCount(name) => {
            // &REQUEST_HEADERS:Name — 1 if header present, 0 if absent.
            let key = name.to_lowercase();
            let count = ctx.headers.iter().filter(|(k, _)| k.to_lowercase() == key).count();
            vec![count.to_string()]
        }

        CrsTarget::ArgsCount => {
            // &ARGS — total number of query + body arguments.
            let mut count = form_count(ctx.query.as_deref().unwrap_or(""));
            if let Some(body) = &ctx.body {
                if is_form_body(ctx) {
                    if let Ok(s) = std::str::from_utf8(body) {
                        count += form_count(s);
                    }
                }
            }
            vec![count.to_string()]
        }
    }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn build_uri(ctx: &RequestContext) -> String {
    match &ctx.query {
        Some(q) if !q.is_empty() => format!("{}?{}", ctx.path, q),
        _ => ctx.path.clone(),
    }
}

fn is_form_body(ctx: &RequestContext) -> bool {
    ctx.headers.iter().any(|(k, v)| {
        k.to_lowercase() == "content-type"
            && v.to_lowercase().contains("application/x-www-form-urlencoded")
    })
}

/// Count the number of parameters in a form-encoded string.
fn form_count(s: &str) -> usize {
    if s.is_empty() { return 0; }
    s.split('&').count()
}

/// Extract decoded values from a form-encoded string (`k=v&k2=v2 ...`).
fn form_values(s: &str) -> Vec<String> {
    if s.is_empty() { return vec![]; }
    s.split('&')
        .map(|pair| {
            let val = pair.find('=').map_or(pair, |i| &pair[i + 1..]);
            pct_decode(val)
        })
        .collect()
}

/// Extract decoded names from a form-encoded string.
fn form_names(s: &str) -> Vec<String> {
    if s.is_empty() { return vec![]; }
    s.split('&')
        .map(|pair| pct_decode(pair.split('=').next().unwrap_or(pair)))
        .collect()
}

fn cookie_values(ctx: &RequestContext) -> Vec<String> {
    cookie_pairs(ctx).into_iter().map(|(_, v)| v).collect()
}
fn cookie_names(ctx: &RequestContext) -> Vec<String> {
    cookie_pairs(ctx).into_iter().map(|(k, _)| k).collect()
}

fn cookie_pairs(ctx: &RequestContext) -> Vec<(String, String)> {
    let header = ctx.headers.iter()
        .find(|(k, _)| k.to_lowercase() == "cookie")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    header.split(';')
        .filter_map(|pair| {
            let mut it = pair.trim().splitn(2, '=');
            let k = it.next()?.trim().to_owned();
            if k.is_empty() { return None; }
            let v = it.next().unwrap_or("").trim().to_owned();
            Some((k, v))
        })
        .collect()
}

fn pct_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
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
