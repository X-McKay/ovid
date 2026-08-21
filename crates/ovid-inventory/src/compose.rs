//! Declared infrastructure from Compose files (FR-011's container
//! metadata, service dimension).
//!
//! A `docker-compose.yml` / `compose.yaml` names the services a repository
//! expects around it — a *declaration* of external systems, parallel to a
//! manifest declaring packages. Parsing is generic (service name, image,
//! published ports); no framework semantics. Declared services are merged
//! with dynamically observed destinations by the pipeline; declaration
//! alone never sets `observed`/`exercised` states (§6.3).

use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};

/// One service declared in a Compose file.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct DeclaredService {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Container-side ports, from `ports:` entries (all common forms) and
    /// `expose:`.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Repository-relative file the declaration came from.
    pub source_file: String,
}

const MAX_COMPOSE_BYTES: u64 = 1024 * 1024;

/// Whether a file basename looks like a Compose file.
fn is_compose_file(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    matches!(
        base,
        "docker-compose.yml"
            | "docker-compose.yaml"
            | "compose.yml"
            | "compose.yaml"
            | "docker-compose.override.yml"
            | "docker-compose.override.yaml"
    )
}

/// Parse the container-side port out of a Compose `ports:` entry.
///
/// Handles `"5432"`, `"5432:5432"`, `"127.0.0.1:15432:5432"`,
/// `"5432:5432/tcp"`, bare integers, and long-syntax maps with `target:`.
fn container_port(entry: &serde_yaml::Value) -> Option<u16> {
    match entry {
        serde_yaml::Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        serde_yaml::Value::String(s) => {
            let no_proto = s.split('/').next().unwrap_or(s);
            no_proto.rsplit(':').next()?.trim().parse().ok()
        }
        serde_yaml::Value::Mapping(m) => m
            .get(serde_yaml::Value::String("target".into()))
            .and_then(|t| t.as_u64())
            .and_then(|p| u16::try_from(p).ok()),
        _ => None,
    }
}

/// Scan a snapshot for Compose files and return every declared service.
pub fn scan_compose(snapshot: &RepoSnapshot) -> Vec<DeclaredService> {
    let mut services = Vec::new();
    let compose_files: Vec<String> = snapshot
        .files
        .keys()
        .filter(|p| is_compose_file(p) && !p.contains("node_modules/") && !p.contains(".venv/"))
        .cloned()
        .collect();
    for path in compose_files {
        let Ok(text) = snapshot.read_file(&path, MAX_COMPOSE_BYTES) else {
            continue;
        };
        let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&text) else {
            continue; // malformed compose: skipped, surfaced via scanned-file absence
        };
        let Some(service_map) = doc.get("services").and_then(|s| s.as_mapping()) else {
            continue;
        };
        for (name, body) in service_map {
            let Some(name) = name.as_str() else { continue };
            let image = body
                .get("image")
                .and_then(|i| i.as_str())
                .map(str::to_string);
            let mut ports: Vec<u16> = Vec::new();
            for key in ["ports", "expose"] {
                if let Some(entries) = body.get(key).and_then(|p| p.as_sequence()) {
                    for entry in entries {
                        if let Some(port) = container_port(entry) {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                }
            }
            services.push(DeclaredService {
                name: name.to_string(),
                image,
                ports,
                source_file: path.clone(),
            });
        }
    }
    services.sort_by(|a, b| a.name.cmp(&b.name));
    services
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    fn snapshot_with_compose(contents: &str) -> RepoSnapshot {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("infra")).unwrap();
        std::fs::write(dir.path().join("infra/docker-compose.yml"), contents).unwrap();
        let snap = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        std::mem::forget(dir);
        snap
    }

    #[test]
    fn parses_services_images_and_port_forms() {
        let services = scan_compose(&snapshot_with_compose(
            r#"
services:
  postgres:
    image: postgres:16
    ports:
      - "127.0.0.1:15432:5432"
  redis:
    image: redis:7
    ports:
      - "6379:6379/tcp"
      - 6380
  broker:
    image: rabbitmq:3
    ports:
      - target: 5672
        published: 5672
  app:
    build: .
    expose:
      - "8080"
"#,
        ));
        assert_eq!(services.len(), 4);
        let postgres = services.iter().find(|s| s.name == "postgres").unwrap();
        assert_eq!(postgres.image.as_deref(), Some("postgres:16"));
        assert_eq!(
            postgres.ports,
            vec![5432],
            "container-side port, not host mapping"
        );
        let redis = services.iter().find(|s| s.name == "redis").unwrap();
        assert_eq!(redis.ports, vec![6379, 6380]);
        let broker = services.iter().find(|s| s.name == "broker").unwrap();
        assert_eq!(broker.ports, vec![5672], "long syntax target");
        let app = services.iter().find(|s| s.name == "app").unwrap();
        assert_eq!(app.image, None);
        assert_eq!(app.ports, vec![8080], "expose entries count");
        assert!(services
            .iter()
            .all(|s| s.source_file == "infra/docker-compose.yml"));
    }

    #[test]
    fn malformed_or_absent_compose_is_empty_not_fatal() {
        let services = scan_compose(&snapshot_with_compose("not: [valid, compose"));
        assert!(services.is_empty());
    }
}
