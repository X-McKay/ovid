//! Declared network endpoints from repository configuration and source
//! (FR-011's service dimension, extended beyond Compose; §6.6, §25.3).
//!
//! Repositories declare the systems they talk to in more places than
//! Compose files: benchmark manifests carry `base_url:` values, configs
//! interpolate `https://${LLM_HOST}/v1`, and code reads `MODEL_ENDPOINT`
//! from the environment. All of these are *declarations* of external
//! connectivity — including the ones whose concrete host is bound only at
//! runtime by an environment variable Ovid cannot see. Per §6.6 the miner
//! records what the text supports and nothing more:
//!
//! - A literal service-scheme URL in a config file becomes a declared
//!   endpoint with host/port/path (trust tier T4: structured metadata).
//! - An env-var placeholder in an endpoint position (`${LLM_HOST}`,
//!   `host_env: LLM_HOST`, `os.environ["LLM_HOST"]`) becomes an
//!   *env-parameterized* endpoint: host unknown-by-construction, but the
//!   surrounding text still yields the scheme, URL path, default value,
//!   and credential variable names — the "how it will be used" details.
//!   Source-mined reads are T5 (textual heuristic): they can propose,
//!   never confirm (ADR-007).
//!
//! Mining is generic string/structure analysis — no framework semantics
//! (ADR-005). Declaration never sets dynamic claim states (§6.3), and only
//! environment variable *names* are recorded, never values (§12.1: no
//! secrets in outputs).

use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a declared endpoint was mined; determines the evidence trust tier.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum EndpointOrigin {
    /// Structured configuration file (T4).
    Config,
    /// Source-code environment read (T5 — proposal only).
    SourceMined,
}

/// One declared network endpoint (concrete or env-parameterized).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct DeclaredEndpoint {
    /// URL scheme when the declaration reveals one (`https`, `postgres`…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Concrete host, or `None` when the host is bound at runtime from an
    /// environment variable (`env_var` then says which).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Explicit port from the declaration (scheme-default resolution is
    /// the pipeline's job, via protocol packs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// URL path, when declared (`/v1`) — how the resource is addressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Environment variable that supplies the host/URL at runtime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    /// Declared default for an env-bound endpoint
    /// (`os.getenv("LLM_HOST", "http://localhost:8000")`); a fallback the
    /// code ships with, not the runtime value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
    /// Environment variable *names* declared alongside as credentials for
    /// this endpoint (`api_key_env: CYBERLAB_MODEL_KEY`). Names only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_env: Vec<String>,
    /// Where it was declared: `file (key.path)` or `file:line (VAR)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    pub origin: EndpointOrigin,
}

impl DeclaredEndpoint {
    /// Stable identity for merging duplicates across files.
    fn identity(&self) -> String {
        match (&self.host, &self.env_var) {
            (Some(host), _) => format!(
                "{}:{}",
                host,
                self.port.map(|p| p.to_string()).unwrap_or_default()
            ),
            (None, Some(var)) => format!("env:{var}"),
            (None, None) => String::new(),
        }
    }
}

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ENDPOINTS: usize = 100;

/// Schemes that imply a network service worth reporting.
const SERVICE_SCHEMES: &[&str] = &[
    "http",
    "https",
    "ws",
    "wss",
    "grpc",
    "grpcs",
    "postgres",
    "postgresql",
    "redis",
    "rediss",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "amqp",
    "amqps",
    "kafka",
    "smtp",
    "smtps",
    "nats",
];

/// Hosts that are ecosystem infrastructure or documentation conventions,
/// not application dependencies: package registries, VCS forges, schema
/// registries, and RFC 2606/6761 reserved names.
fn is_uninteresting_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    // Loopback / unspecified: not *external* connectivity.
    if host == "localhost"
        || host == "0.0.0.0"
        || host == "::1"
        || host.starts_with("127.")
        || host.ends_with(".localhost")
    {
        return true;
    }
    // Reserved documentation names.
    for suffix in [".example", ".invalid", ".test"] {
        if host.ends_with(suffix) {
            return true;
        }
    }
    if host == "example.com"
        || host == "example.org"
        || host == "example.net"
        || host.ends_with(".example.com")
        || host.ends_with(".example.org")
        || host.ends_with(".example.net")
    {
        return true;
    }
    const INFRA: &[&str] = &[
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "codeload.github.com",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "proxy.golang.org",
        "sum.golang.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "rubygems.org",
        "packagist.org",
        "schema.org",
        "json-schema.org",
        "json.schemastore.org",
        "www.w3.org",
        "xmlns.com",
        "purl.org",
        "opensource.org",
        "creativecommons.org",
    ];
    INFRA
        .iter()
        .any(|i| host == *i || host.ends_with(&format!(".{i}")))
}

/// Whether a key/variable name is endpoint-shaped: its last `_` token
/// names a place things connect to.
fn is_endpoint_name(name: &str) -> bool {
    let last = name
        .rsplit(['_', '-'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    matches!(
        last.as_str(),
        "host"
            | "hosts"
            | "url"
            | "uri"
            | "endpoint"
            | "endpoints"
            | "addr"
            | "address"
            | "server"
            | "dsn"
            | "broker"
            | "gateway"
    )
}

/// Whether a `*_env`-style key names a credential rather than an address.
fn is_credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "key",
        "token",
        "secret",
        "password",
        "passwd",
        "credential",
        "auth",
    ]
    .iter()
    .any(|t| lower.contains(t))
}

fn looks_like_env_name(value: &str) -> bool {
    value.len() >= 3
        && value.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Extract `${VAR}` / `$VAR` / `{{VAR}}` / `%(VAR)s` from a string, if the
/// whole placeholder family appears.
fn placeholder_env_var(value: &str) -> Option<String> {
    let re = regex_placeholder();
    re.captures(value).map(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .or_else(|| c.get(3))
            .or_else(|| c.get(4))
            .map(|m| m.as_str().to_string())
            .unwrap_or_default()
    })
}

fn regex_placeholder() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}|\$([A-Z_][A-Z0-9_]{2,})|\{\{\s*(?:\.?[Ee]nv\.?\s*)?([A-Z_][A-Z0-9_]{2,})\s*\}\}|%\(([A-Z_][A-Z0-9_]{2,})\)s",
        )
        .expect("placeholder regex")
    })
}

/// Parse `scheme://[cred@]host[:port][/path]` by hand (no url crate).
/// Returns None when the scheme is not service-shaped or host is empty.
struct ParsedUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: Option<String>,
    host_is_placeholder: Option<String>,
}

fn parse_service_url(raw: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if !SERVICE_SCHEMES.contains(&scheme.as_str()) {
        return None;
    }
    let rest = rest.trim_end_matches(['"', '\'', ',', ')', ']', '}', '>', '.', ';']);
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    // Strip userinfo; never keep credentials (§12.1). A password embedded
    // in a URL is intentionally not recorded anywhere.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let host_is_placeholder = placeholder_env_var(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse::<u16>().ok())
        }
        _ => (authority.to_string(), None),
    };
    if host.is_empty() {
        return None;
    }
    let path = path.filter(|p| p.len() > 1).map(|p| {
        // Bound and strip query/fragment: addressing detail only.
        let p = p.split(['?', '#']).next().unwrap_or(&p);
        p.chars().take(120).collect::<String>()
    });
    Some(ParsedUrl {
        scheme,
        host,
        port,
        path,
        host_is_placeholder,
    })
}

/// File classification.
fn config_kind(path: &str) -> Option<&'static str> {
    if path.contains("node_modules/") || path.contains(".venv/") || path.contains("vendor/") {
        return None;
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    let lower = base.to_ascii_lowercase();
    // Lockfiles pin registries, not application endpoints.
    if lower.ends_with(".lock")
        || lower == "package-lock.json"
        || lower == "yarn.lock"
        || lower == "pnpm-lock.yaml"
        || lower == "go.sum"
    {
        return None;
    }
    if lower.starts_with(".env") {
        return Some("env");
    }
    match lower.rsplit('.').next().unwrap_or("") {
        "yaml" | "yml" => Some("yaml"),
        "json" => Some("json"),
        "toml" => Some("toml"),
        "ini" | "cfg" | "conf" | "properties" | "env" => Some("env"),
        _ => None,
    }
}

fn is_source_file(path: &str) -> bool {
    if path.contains("node_modules/") || path.contains(".venv/") || path.contains("vendor/") {
        return false;
    }
    matches!(
        path.rsplit('.').next().unwrap_or(""),
        "py" | "js"
            | "ts"
            | "tsx"
            | "jsx"
            | "mjs"
            | "cjs"
            | "go"
            | "rs"
            | "rb"
            | "java"
            | "kt"
            | "sh"
            | "bash"
    )
}

/// Mine every declared endpoint from a snapshot.
pub fn scan_endpoints(snapshot: &RepoSnapshot) -> Vec<DeclaredEndpoint> {
    let mut found: Vec<DeclaredEndpoint> = Vec::new();
    let paths: Vec<String> = snapshot.files.keys().cloned().collect();
    for path in &paths {
        if found.len() >= MAX_ENDPOINTS {
            break;
        }
        if let Some(kind) = config_kind(path) {
            let Ok(text) = snapshot.read_file(path, MAX_FILE_BYTES) else {
                continue;
            };
            match kind {
                "yaml" => {
                    if let Ok(v) = serde_yaml::from_str::<serde_yaml::Value>(&text) {
                        if let Ok(v) = serde_json::to_value(&v) {
                            walk_config(&v, path, &mut String::new(), &mut found);
                        }
                    }
                }
                "json" => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                        walk_config(&v, path, &mut String::new(), &mut found);
                    }
                }
                "toml" => {
                    if let Ok(v) = toml::from_str::<toml::Value>(&text) {
                        if let Ok(v) = serde_json::to_value(&v) {
                            walk_config(&v, path, &mut String::new(), &mut found);
                        }
                    }
                }
                _ => scan_env_style(&text, path, &mut found),
            }
        } else if is_source_file(path) {
            let Ok(text) = snapshot.read_file(path, MAX_FILE_BYTES) else {
                continue;
            };
            scan_source(&text, path, &mut found);
        }
    }
    merge(found)
}

/// One string value found in a config position.
fn classify_config_value(
    key_path: &str,
    key: &str,
    value: &str,
    file: &str,
) -> Option<DeclaredEndpoint> {
    let source = format!("{file} ({key_path})");
    // Literal or placeholder URL.
    if let Some(url) = parse_service_url(value) {
        if let Some(var) = url.host_is_placeholder {
            return Some(DeclaredEndpoint {
                scheme: Some(url.scheme),
                host: None,
                port: url.port,
                path: url.path,
                env_var: Some(var),
                default_value: None,
                credential_env: Vec::new(),
                sources: vec![source],
                origin: EndpointOrigin::Config,
            });
        }
        if is_uninteresting_host(&url.host) {
            return None;
        }
        return Some(DeclaredEndpoint {
            scheme: Some(url.scheme),
            host: Some(url.host),
            port: url.port,
            path: url.path,
            env_var: None,
            default_value: None,
            credential_env: Vec::new(),
            sources: vec![source],
            origin: EndpointOrigin::Config,
        });
    }
    // Endpoint-shaped key whose value is a bare placeholder:
    // `host: ${LLM_HOST}`.
    if is_endpoint_name(key) {
        if let Some(var) = placeholder_env_var(value) {
            if value.trim().len() <= var.len() + 6 {
                return Some(DeclaredEndpoint {
                    scheme: None,
                    host: None,
                    port: None,
                    path: None,
                    env_var: Some(var),
                    default_value: None,
                    credential_env: Vec::new(),
                    sources: vec![source],
                    origin: EndpointOrigin::Config,
                });
            }
        }
    }
    // Indirection convention: `base_url_env: LLM_HOST` names the variable
    // that will hold the endpoint.
    if let Some(stem) = key
        .strip_suffix("_env")
        .or_else(|| key.strip_suffix("_ENV"))
    {
        if is_endpoint_name(stem) && looks_like_env_name(value.trim()) {
            return Some(DeclaredEndpoint {
                scheme: None,
                host: None,
                port: None,
                path: None,
                env_var: Some(value.trim().to_string()),
                default_value: None,
                credential_env: Vec::new(),
                sources: vec![source],
                origin: EndpointOrigin::Config,
            });
        }
    }
    None
}

/// Recursive config walk. Endpoints found directly in a mapping absorb
/// credential-env declarations (`api_key_env: NAME`) from that same
/// mapping — the sibling relationship is the association evidence.
fn walk_config(
    value: &serde_json::Value,
    file: &str,
    key_path: &mut String,
    out: &mut Vec<DeclaredEndpoint>,
) {
    match value {
        serde_json::Value::Object(map) => {
            let mut local: Vec<DeclaredEndpoint> = Vec::new();
            let mut creds: Vec<String> = Vec::new();
            for (key, child) in map {
                let saved = key_path.len();
                if !key_path.is_empty() {
                    key_path.push('.');
                }
                key_path.push_str(key);
                match child {
                    serde_json::Value::String(s) => {
                        if let Some(endpoint) = classify_config_value(key_path, key, s, file) {
                            local.push(endpoint);
                        } else if (key.ends_with("_env") || key.ends_with("_ENV"))
                            && is_credential_name(key)
                            && looks_like_env_name(s.trim())
                        {
                            creds.push(s.trim().to_string());
                        }
                    }
                    _ => walk_config(child, file, key_path, out),
                }
                key_path.truncate(saved);
            }
            for mut endpoint in local {
                endpoint.credential_env = creds.clone();
                out.push(endpoint);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                walk_config(item, file, key_path, out);
            }
        }
        _ => {}
    }
}

/// `.env` / ini-style line mining: `KEY=value` (or `key = value`).
fn scan_env_style(text: &str, file: &str, out: &mut Vec<DeclaredEndpoint>) {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().trim_start_matches("export ").trim();
        let value = value.trim().trim_matches(['"', '\'']);
        if let Some(endpoint) = classify_config_value(key, key, value, file) {
            out.push(endpoint);
        }
    }
}

fn regex_getenv() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(concat!(
            r#"(?:os\.environ\.get|os\.environ|os\.getenv|process\.env|env::var(?:_os)?|"#,
            r#"os\.Getenv|System\.getenv|ENV\.fetch|ENV)"#,
            r#"[\[\(\.]{1,2}\s*["']?([A-Z][A-Z0-9_]{2,})["']?"#,
        ))
        .expect("getenv regex")
    })
}

fn regex_scheme_template() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // Literal alternation, not a generic scheme class: in squashed
        // source lines an f-string prefix would otherwise glue onto the
        // scheme (`f"https` -> `fhttps`) and a generic class would match
        // the junk. The engine starts at the first real scheme letter.
        regex::Regex::new(concat!(
            r"(?:https?|wss?|grpcs?|postgresql|postgres|rediss?|mysql|",
            r"mongodb(?:\+srv)?|amqps?|kafka|smtps?|nats)://[^\s\x22']*",
        ))
        .expect("scheme regex")
    })
}

fn regex_getenv_default() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // getenv("NAME", "default") / ENV.fetch("NAME", "default")
        regex::Regex::new(r#"["']([A-Z][A-Z0-9_]{2,})["']\s*,\s*["']([^"']+)["']"#)
            .expect("getenv default regex")
    })
}

/// Source mining: environment reads of endpoint-named variables. T5 —
/// textual evidence of intent, never confirmation.
fn scan_source(text: &str, file: &str, out: &mut Vec<DeclaredEndpoint>) {
    let getenv = regex_getenv();
    for (index, line) in text.lines().enumerate() {
        // Comments are still declarations of nothing; skip the obvious.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            continue;
        }
        for capture in getenv.captures_iter(line) {
            let var = capture.get(1).map(|m| m.as_str()).unwrap_or_default();
            if !is_endpoint_name(var) {
                continue;
            }
            let source = format!("{file}:{} ({var})", index + 1);
            // Same-line URL template reveals scheme/path:
            // f"https://{os.environ['LLM_HOST']}/v1".
            let mut scheme = None;
            let mut path = None;
            let mut port = None;
            let mut default_value = None;
            // Quotes inside f-string/template interpolation split the URL
            // across the regex; squash them so the template reads as one
            // token (host junk is ignored — only scheme/port/path are used).
            let squashed = line.replace(['"', '\''], "");
            if let Some(m) = regex_scheme_template().find(&squashed) {
                if let Some(url) = parse_service_url(m.as_str()) {
                    scheme = Some(url.scheme);
                    path = url.path;
                    port = url.port;
                }
            }
            if let Some(default) = regex_getenv_default().captures(line) {
                if default.get(1).map(|m| m.as_str()) == Some(var) {
                    let value = default.get(2).map(|m| m.as_str()).unwrap_or_default();
                    default_value = Some(value.chars().take(200).collect());
                    if scheme.is_none() {
                        if let Some(url) = parse_service_url(value) {
                            scheme = Some(url.scheme);
                            path = url.path;
                            port = url.port;
                        }
                    }
                }
            }
            out.push(DeclaredEndpoint {
                scheme,
                host: None,
                port,
                path,
                env_var: Some(var.to_string()),
                default_value,
                credential_env: Vec::new(),
                sources: vec![source],
                origin: EndpointOrigin::SourceMined,
            });
        }
    }
}

/// Merge duplicates: same concrete host:port, or same env var. Config
/// origin outranks source-mined; details fill in from any duplicate.
fn merge(found: Vec<DeclaredEndpoint>) -> Vec<DeclaredEndpoint> {
    let mut merged: BTreeMap<String, DeclaredEndpoint> = BTreeMap::new();
    for endpoint in found {
        let key = endpoint.identity();
        if key.is_empty() {
            continue;
        }
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, endpoint);
            }
            Some(existing) => {
                if existing.origin == EndpointOrigin::SourceMined
                    && endpoint.origin == EndpointOrigin::Config
                {
                    existing.origin = EndpointOrigin::Config;
                }
                if existing.scheme.is_none() {
                    existing.scheme = endpoint.scheme.clone();
                }
                if existing.path.is_none() {
                    existing.path = endpoint.path.clone();
                }
                if existing.port.is_none() {
                    existing.port = endpoint.port;
                }
                if existing.default_value.is_none() {
                    existing.default_value = endpoint.default_value.clone();
                }
                for cred in endpoint.credential_env {
                    if !existing.credential_env.contains(&cred) {
                        existing.credential_env.push(cred);
                    }
                }
                for source in endpoint.sources {
                    if !existing.sources.contains(&source) && existing.sources.len() < 12 {
                        existing.sources.push(source);
                    }
                }
            }
        }
    }
    merged.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    fn snapshot_with(files: &[(&str, &str)]) -> RepoSnapshot {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, contents).unwrap();
        }
        let snap = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        std::mem::forget(dir);
        snap
    }

    #[test]
    fn literal_config_url_with_sibling_credential_env() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "manifests/run.yaml",
            r#"
model_endpoint:
  base_url: https://llm.lab-example-host.io/v1
  model_id: some-model
  api_key_env: MODEL_API_KEY
"#,
        )]));
        assert_eq!(endpoints.len(), 1);
        let e = &endpoints[0];
        assert_eq!(e.scheme.as_deref(), Some("https"));
        assert_eq!(e.host.as_deref(), Some("llm.lab-example-host.io"));
        assert_eq!(e.path.as_deref(), Some("/v1"));
        assert_eq!(e.credential_env, vec!["MODEL_API_KEY".to_string()]);
        assert_eq!(e.origin, EndpointOrigin::Config);
        assert!(e.sources[0].contains("model_endpoint.base_url"));
    }

    #[test]
    fn env_placeholder_in_url_keeps_scheme_and_path() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "config/app.yaml",
            "telemetry:\n  collector: https://${TELEMETRY_HOST}/ingest\n",
        )]));
        assert_eq!(endpoints.len(), 1);
        let e = &endpoints[0];
        assert_eq!(e.host, None, "host is runtime-bound");
        assert_eq!(e.env_var.as_deref(), Some("TELEMETRY_HOST"));
        assert_eq!(e.scheme.as_deref(), Some("https"));
        assert_eq!(e.path.as_deref(), Some("/ingest"));
    }

    #[test]
    fn endpoint_key_with_bare_placeholder_and_env_suffix_convention() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "config/db.yaml",
            "database:\n  host: ${DB_HOST}\nmodel:\n  base_url_env: LLM_HOST\n",
        )]));
        let vars: Vec<_> = endpoints.iter().filter_map(|e| e.env_var.clone()).collect();
        assert!(vars.contains(&"DB_HOST".to_string()));
        assert!(vars.contains(&"LLM_HOST".to_string()));
    }

    #[test]
    fn source_mined_getenv_with_template_and_default() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "app/client.py",
            concat!(
                "import os\n",
                "base = f\"https://{os.environ['INFERENCE_HOST']}/v2/complete\"\n",
                "fallback = os.getenv(\"MODEL_URL\", \"http://models.internal:8080/v1\")\n",
                "irrelevant = os.getenv(\"LOG_LEVEL\", \"info\")\n",
            ),
        )]));
        assert_eq!(endpoints.len(), 2, "LOG_LEVEL is not endpoint-shaped");
        let inference = endpoints
            .iter()
            .find(|e| e.env_var.as_deref() == Some("INFERENCE_HOST"))
            .unwrap();
        assert_eq!(inference.scheme.as_deref(), Some("https"));
        assert_eq!(inference.path.as_deref(), Some("/v2/complete"));
        assert_eq!(inference.origin, EndpointOrigin::SourceMined);
        assert!(inference.sources[0].contains("app/client.py:2"));
        let model = endpoints
            .iter()
            .find(|e| e.env_var.as_deref() == Some("MODEL_URL"))
            .unwrap();
        assert_eq!(model.scheme.as_deref(), Some("http"));
        assert_eq!(model.port, Some(8080));
        assert_eq!(
            model.default_value.as_deref(),
            Some("http://models.internal:8080/v1")
        );
    }

    #[test]
    fn infrastructure_and_loopback_hosts_are_excluded() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "config/misc.yaml",
            concat!(
                "schema: \"https://json-schema.org/draft/2020-12/schema\"\n",
                "repo: https://github.com/acme/tool\n",
                "index: https://pypi.org/simple\n",
                "local: http://127.0.0.1:8000/health\n",
                "docs: https://docs.example.com/guide\n",
                "real: https://api.acme-service.io/v1\n",
            ),
        )]));
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].host.as_deref(), Some("api.acme-service.io"));
    }

    #[test]
    fn lockfiles_and_markdown_are_not_mined() {
        let endpoints = scan_endpoints(&snapshot_with(&[
            (
                "uv.lock",
                "[[package]]\nurl = \"https://real-service.io/api\"\n",
            ),
            ("README.md", "See https://real-service.io/api\n"),
            ("package-lock.json", r#"{"u": "https://real-service.io/x"}"#),
        ]));
        assert!(endpoints.is_empty());
    }

    #[test]
    fn duplicates_merge_across_files_with_config_outranking_source() {
        let endpoints = scan_endpoints(&snapshot_with(&[
            (
                "a/run.yaml",
                "endpoint:\n  base_url: https://svc.acme-lab.io/v1\n",
            ),
            (
                "b/run.yaml",
                "endpoint:\n  base_url: https://svc.acme-lab.io/v1\n",
            ),
            ("code.py", "u = os.environ[\"SVC_URL\"]\n"),
            ("code2.py", "u2 = os.getenv(\"SVC_URL\")\n"),
        ]));
        assert_eq!(endpoints.len(), 2);
        let concrete = endpoints.iter().find(|e| e.host.is_some()).unwrap();
        assert_eq!(concrete.sources.len(), 2, "same URL in two files merges");
        let env = endpoints.iter().find(|e| e.host.is_none()).unwrap();
        assert_eq!(env.env_var.as_deref(), Some("SVC_URL"));
        assert_eq!(env.sources.len(), 2);
    }

    #[test]
    fn credentials_in_url_userinfo_are_never_recorded() {
        let endpoints = scan_endpoints(&snapshot_with(&[(
            "config/db.toml",
            "[db]\nurl = \"postgres://admin:hunter2@db.acme-lab.io:5432/app\"\n",
        )]));
        assert_eq!(endpoints.len(), 1);
        let serialized = serde_json::to_string(&endpoints).unwrap();
        assert!(!serialized.contains("hunter2"), "no secrets in outputs");
        assert!(!serialized.contains("admin"));
        assert_eq!(endpoints[0].host.as_deref(), Some("db.acme-lab.io"));
        assert_eq!(endpoints[0].port, Some(5432));
    }
}
