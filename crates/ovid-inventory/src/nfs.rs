//! Declared NFS mounts from deployment metadata (spec §10.1, §13.7).
//!
//! This scanner never contacts an NFS server and never mounts anything.
//! It extracts server/export/mount-path relationships from Compose and
//! Kubernetes YAML so a later isolated run can correlate failed file
//! operations with the storage declaration.

use ovid_repository::RepoSnapshot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_YAML_BYTES: u64 = 1024 * 1024;

/// One NFS export mapped into a declared service/container path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DeclaredNfsMount {
    pub server: String,
    pub export: String,
    pub mount_point: String,
    /// `nfs` or `nfs4` when the declaration distinguishes them.
    pub fs_type: String,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Repository-relative declaration file.
    pub source_file: String,
    /// `compose` or `kubernetes`.
    pub source_kind: String,
}

impl DeclaredNfsMount {
    pub fn identity(&self) -> String {
        format!("{}:{}", self.server, self.export)
    }
}

/// Scan Compose and Kubernetes YAML for NFS volume declarations.
pub fn scan_declared_nfs(snapshot: &RepoSnapshot) -> Vec<DeclaredNfsMount> {
    let mut declarations = Vec::new();
    for path in snapshot.files.keys().filter(|path| {
        (path.ends_with(".yml") || path.ends_with(".yaml"))
            && !path.contains("node_modules/")
            && !path.contains(".venv/")
    }) {
        let Ok(text) = snapshot.read_file(path, MAX_YAML_BYTES) else {
            continue;
        };
        let documents: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(&text)
            .filter_map(|document| serde_yaml::Value::deserialize(document).ok())
            .collect();
        for document in documents {
            scan_compose_document(path, &document, &mut declarations);
            scan_kubernetes_document(path, &document, &mut declarations);
        }
    }
    declarations.sort_by(|a, b| {
        (&a.server, &a.export, &a.mount_point, &a.source_file).cmp(&(
            &b.server,
            &b.export,
            &b.mount_point,
            &b.source_file,
        ))
    });
    declarations.dedup();
    declarations
}

#[derive(Clone)]
struct ComposeVolume {
    server: String,
    export: String,
    fs_type: String,
    read_only: bool,
}

fn scan_compose_document(
    path: &str,
    document: &serde_yaml::Value,
    out: &mut Vec<DeclaredNfsMount>,
) {
    let Some(services) = document
        .get("services")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return;
    };
    let Some(volumes) = document
        .get("volumes")
        .and_then(serde_yaml::Value::as_mapping)
    else {
        return;
    };
    let mut nfs_volumes: BTreeMap<String, ComposeVolume> = BTreeMap::new();
    for (name, body) in volumes {
        let (Some(name), Some(options)) = (
            name.as_str(),
            body.get("driver_opts")
                .and_then(serde_yaml::Value::as_mapping),
        ) else {
            continue;
        };
        let fs_type = mapping_string(options, "type").unwrap_or_default();
        if fs_type != "nfs" && fs_type != "nfs4" {
            continue;
        }
        let option_text = mapping_string(options, "o").unwrap_or_default();
        let flags: Vec<&str> = option_text.split(',').map(str::trim).collect();
        let option_server = flags.iter().find_map(|flag| {
            flag.strip_prefix("addr=")
                .or_else(|| flag.strip_prefix("host="))
        });
        let device = mapping_string(options, "device").unwrap_or_default();
        let (device_server, export) = split_nfs_device(device);
        let Some(server) = device_server.or(option_server) else {
            continue;
        };
        let Some(export) = export else { continue };
        nfs_volumes.insert(
            name.to_string(),
            ComposeVolume {
                server: server.to_string(),
                export: export.to_string(),
                fs_type: fs_type.to_string(),
                read_only: flags.contains(&"ro"),
            },
        );
    }

    for (service_name, body) in services {
        let Some(service_name) = service_name.as_str() else {
            continue;
        };
        let Some(entries) = body.get("volumes").and_then(serde_yaml::Value::as_sequence) else {
            continue;
        };
        for entry in entries {
            let parsed = match entry {
                serde_yaml::Value::String(value) => parse_compose_mount_string(value),
                serde_yaml::Value::Mapping(mapping) => {
                    match (
                        mapping_string(mapping, "source"),
                        mapping_string(mapping, "target"),
                    ) {
                        (Some(source), Some(target)) => {
                            let read_only = mapping
                                .get(serde_yaml::Value::String("read_only".into()))
                                .and_then(serde_yaml::Value::as_bool)
                                .unwrap_or(false);
                            Some((source, target, read_only))
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some((source, target, mount_read_only)) = parsed else {
                continue;
            };
            let Some(volume) = nfs_volumes.get(source) else {
                continue;
            };
            if !target.starts_with('/') {
                continue;
            }
            out.push(DeclaredNfsMount {
                server: volume.server.clone(),
                export: volume.export.clone(),
                mount_point: target.to_string(),
                fs_type: volume.fs_type.clone(),
                read_only: volume.read_only || mount_read_only,
                service: Some(service_name.to_string()),
                source_file: path.to_string(),
                source_kind: "compose".into(),
            });
        }
    }
}

fn mapping_string<'a>(mapping: &'a serde_yaml::Mapping, key: &str) -> Option<&'a str> {
    mapping
        .get(serde_yaml::Value::String(key.into()))
        .and_then(serde_yaml::Value::as_str)
}

fn split_nfs_device(device: &str) -> (Option<&str>, Option<&str>) {
    if let Some(export) = device.strip_prefix(':') {
        return (None, export.starts_with('/').then_some(export));
    }
    let Some((server, export)) = device.rsplit_once(':') else {
        return (None, None);
    };
    (
        (!server.is_empty()).then_some(server.trim_matches(['[', ']'])),
        export.starts_with('/').then_some(export),
    )
}

fn parse_compose_mount_string(value: &str) -> Option<(&str, &str, bool)> {
    let mut fields = value.split(':');
    let source = fields.next()?;
    let target = fields.next()?;
    let options = fields.next().unwrap_or_default();
    Some((
        source,
        target,
        options.split(',').any(|option| option == "ro"),
    ))
}

fn scan_kubernetes_document(
    path: &str,
    document: &serde_yaml::Value,
    out: &mut Vec<DeclaredNfsMount>,
) {
    // A Kubernetes List contains independent resources. Scan each item in
    // isolation so equal volume names in different workloads cannot be joined.
    if document.get("kind").and_then(serde_yaml::Value::as_str) == Some("List") {
        if let Some(items) = document
            .get("items")
            .and_then(serde_yaml::Value::as_sequence)
        {
            for item in items {
                scan_kubernetes_document(path, item, out);
            }
        }
        return;
    }
    let service = document
        .get("metadata")
        .and_then(|metadata| metadata.get("name"))
        .and_then(serde_yaml::Value::as_str)
        .map(str::to_string);
    let mut volumes: BTreeMap<String, (String, String, bool)> = BTreeMap::new();
    let mut mounts: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    collect_kubernetes_nfs(document, &mut volumes, &mut mounts);
    for (name, (server, export, volume_read_only)) in volumes {
        let Some(paths) = mounts.get(&name) else {
            continue;
        };
        for (mount_point, mount_read_only) in paths {
            out.push(DeclaredNfsMount {
                server: server.clone(),
                export: export.clone(),
                mount_point: mount_point.clone(),
                fs_type: "nfs".into(),
                read_only: volume_read_only || *mount_read_only,
                service: service.clone(),
                source_file: path.to_string(),
                source_kind: "kubernetes".into(),
            });
        }
    }
}

fn collect_kubernetes_nfs(
    value: &serde_yaml::Value,
    volumes: &mut BTreeMap<String, (String, String, bool)>,
    mounts: &mut BTreeMap<String, Vec<(String, bool)>>,
) {
    match value {
        serde_yaml::Value::Mapping(mapping) => {
            if let Some(entries) = mapping
                .get(serde_yaml::Value::String("volumes".into()))
                .and_then(serde_yaml::Value::as_sequence)
            {
                for entry in entries {
                    let (Some(name), Some(nfs)) = (
                        entry.get("name").and_then(serde_yaml::Value::as_str),
                        entry.get("nfs"),
                    ) else {
                        continue;
                    };
                    let (Some(server), Some(export)) = (
                        nfs.get("server").and_then(serde_yaml::Value::as_str),
                        nfs.get("path").and_then(serde_yaml::Value::as_str),
                    ) else {
                        continue;
                    };
                    if server.is_empty() || !export.starts_with('/') {
                        continue;
                    }
                    let read_only = nfs
                        .get("readOnly")
                        .and_then(serde_yaml::Value::as_bool)
                        .unwrap_or(false);
                    volumes.insert(
                        name.to_string(),
                        (server.to_string(), export.to_string(), read_only),
                    );
                }
            }
            if let Some(entries) = mapping
                .get(serde_yaml::Value::String("volumeMounts".into()))
                .and_then(serde_yaml::Value::as_sequence)
            {
                for entry in entries {
                    let (Some(name), Some(mount_point)) = (
                        entry.get("name").and_then(serde_yaml::Value::as_str),
                        entry.get("mountPath").and_then(serde_yaml::Value::as_str),
                    ) else {
                        continue;
                    };
                    if !mount_point.starts_with('/') {
                        continue;
                    }
                    let read_only = entry
                        .get("readOnly")
                        .and_then(serde_yaml::Value::as_bool)
                        .unwrap_or(false);
                    mounts
                        .entry(name.to_string())
                        .or_default()
                        .push((mount_point.to_string(), read_only));
                }
            }
            for child in mapping.values() {
                collect_kubernetes_nfs(child, volumes, mounts);
            }
        }
        serde_yaml::Value::Sequence(sequence) => {
            for child in sequence {
                collect_kubernetes_nfs(child, volumes, mounts);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    fn snapshot(files: &[(&str, &str)]) -> RepoSnapshot {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        std::mem::forget(dir);
        snapshot
    }

    #[test]
    fn discovers_compose_nfs_volume_without_mounting_it() {
        let snapshot = snapshot(&[(
            "compose.yaml",
            r#"
services:
  app:
    image: app:test
    volumes:
      - models:/srv/models:ro
volumes:
  models:
    driver: local
    driver_opts:
      type: nfs4
      o: addr=files.internal,rw,nfsvers=4
      device: :/exports/models
"#,
        )]);
        let declarations = scan_declared_nfs(&snapshot);
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].identity(), "files.internal:/exports/models");
        assert_eq!(declarations[0].mount_point, "/srv/models");
        assert!(
            declarations[0].read_only,
            "service mount overrides volume rw"
        );
    }

    #[test]
    fn discovers_direct_kubernetes_nfs_volume_and_container_path() {
        let snapshot = snapshot(&[(
            "deploy/app.yaml",
            r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: model-api
spec:
  template:
    spec:
      volumes:
        - name: models
          nfs:
            server: 10.0.0.8
            path: /exports/models
            readOnly: true
      containers:
        - name: app
          image: app:test
          volumeMounts:
            - name: models
              mountPath: /srv/models
"#,
        )]);
        let declarations = scan_declared_nfs(&snapshot);
        assert_eq!(declarations.len(), 1);
        assert_eq!(declarations[0].server, "10.0.0.8");
        assert_eq!(declarations[0].service.as_deref(), Some("model-api"));
        assert_eq!(declarations[0].source_kind, "kubernetes");
    }

    #[test]
    fn keeps_kubernetes_list_items_isolated() {
        let snapshot = snapshot(&[(
            "deploy/list.yaml",
            r#"
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata:
      name: first
    spec:
      volumes:
        - name: data
          nfs:
            server: first.internal
            path: /first
      containers:
        - name: app
          volumeMounts:
            - name: data
              mountPath: /srv/first
  - apiVersion: v1
    kind: Pod
    metadata:
      name: second
    spec:
      volumes:
        - name: data
          nfs:
            server: second.internal
            path: /second
      containers:
        - name: app
          volumeMounts:
            - name: data
              mountPath: /srv/second
"#,
        )]);
        let declarations = scan_declared_nfs(&snapshot);
        assert_eq!(declarations.len(), 2);
        assert!(declarations.iter().any(|declaration| {
            declaration.server == "first.internal"
                && declaration.mount_point == "/srv/first"
                && declaration.service.as_deref() == Some("first")
        }));
        assert!(declarations.iter().any(|declaration| {
            declaration.server == "second.internal"
                && declaration.mount_point == "/srv/second"
                && declaration.service.as_deref() == Some("second")
        }));
    }
}
