//! Package URL construction (FR-072).
//!
//! Minimal purl builder covering the ecosystems the native scanners emit.
//! Reference: <https://github.com/package-url/purl-spec>.

/// Build a purl string for `ecosystem`/`name`@`version`.
///
/// - `pypi` names are normalized to lowercase with `_` -> `-` per the spec;
/// - `maven` names are expected as `group:artifact` and rendered as
///   `pkg:maven/group/artifact`;
/// - npm scoped names keep their `@scope/` prefix percent-encoded per the
///   purl spec (`%40scope`).
pub fn purl(ecosystem: &str, name: &str, version: Option<&str>) -> String {
    let path = match ecosystem {
        "pypi" => name.to_lowercase().replace('_', "-"),
        "maven" => name.replacen(':', "/", 1),
        "npm" => {
            if let Some(rest) = name.strip_prefix('@') {
                format!("%40{rest}")
            } else {
                name.to_string()
            }
        }
        _ => name.to_string(),
    };
    match version {
        Some(v) => format!("pkg:{ecosystem}/{path}@{v}"),
        None => format!("pkg:{ecosystem}/{path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_ecosystems() {
        assert_eq!(purl("cargo", "serde", Some("1.0.200")), "pkg:cargo/serde@1.0.200");
        assert_eq!(purl("golang", "github.com/gin-gonic/gin", Some("v1.10.0")),
            "pkg:golang/github.com/gin-gonic/gin@v1.10.0");
    }

    #[test]
    fn pypi_is_normalized() {
        assert_eq!(purl("pypi", "Flask_Login", Some("0.6.3")), "pkg:pypi/flask-login@0.6.3");
    }

    #[test]
    fn maven_coordinates_split() {
        assert_eq!(
            purl("maven", "org.apache.kafka:kafka-clients", Some("3.7.0")),
            "pkg:maven/org.apache.kafka/kafka-clients@3.7.0"
        );
    }

    #[test]
    fn npm_scope_is_encoded() {
        assert_eq!(purl("npm", "@types/node", Some("20.0.0")), "pkg:npm/%40types/node@20.0.0");
    }

    #[test]
    fn versionless_purl_has_no_at() {
        assert_eq!(purl("cargo", "serde", None), "pkg:cargo/serde");
    }
}
