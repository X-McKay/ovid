//! Java/JVM: Maven `pom.xml` and Gradle build files (declared).
//!
//! Both parsers are deliberately tolerant text extractors, not full XML/DSL
//! parsers: they cover the overwhelmingly common shapes and record a
//! warning when nothing could be extracted from a present file. Resolved
//! versions for JVM builds generally require the build tool itself
//! (§28.3), which belongs to runner-recipe execution, not static scanning.

use super::{read_or_warn, Scanner};
use crate::{purl, Component, InventoryReport, Scope};
use ovid_core::{ClaimState, ClaimStates};
use ovid_repository::RepoSnapshot;
use regex::Regex;
use std::sync::OnceLock;

pub struct JavaScanner;

impl Scanner for JavaScanner {
    fn name(&self) -> &'static str {
        "java"
    }

    fn scan(&self, snapshot: &RepoSnapshot, report: &mut InventoryReport) {
        for path in snapshot.find_files_named("pom.xml") {
            let path = path.to_string();
            if let Some(text) = read_or_warn(snapshot, &path, report) {
                scan_pom(&text, &path, report);
            }
        }
        for name in ["build.gradle", "build.gradle.kts"] {
            for path in snapshot.find_files_named(name) {
                let path = path.to_string();
                if let Some(text) = read_or_warn(snapshot, &path, report) {
                    scan_gradle(&text, &path, report);
                }
            }
        }
    }
}

fn declared(
    group: &str,
    artifact: &str,
    version: Option<&str>,
    scope: Scope,
    source: &str,
) -> Component {
    let name = format!("{group}:{artifact}");
    Component {
        purl: purl("maven", &name, version),
        name,
        version: version.map(String::from),
        ecosystem: "maven".into(),
        scope,
        direct: true,
        states: ClaimStates::default().with(ClaimState::Declared),
        source_file: source.to_string(),
    }
}

fn tag<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = block.find(&open)? + open.len();
    let end = block[start..].find(&close)? + start;
    Some(block[start..end].trim())
}

fn scan_pom(text: &str, source: &str, report: &mut InventoryReport) {
    let mut rest = text;
    let mut found = false;
    while let Some(start) = rest.find("<dependency>") {
        let Some(end) = rest[start..].find("</dependency>") else {
            break;
        };
        let block = &rest[start..start + end];
        if let (Some(group), Some(artifact)) = (tag(block, "groupId"), tag(block, "artifactId")) {
            // Property placeholders like `${x.version}` are unresolved
            // declarations; keep them versionless rather than invent one.
            let version = tag(block, "version").filter(|v| !v.contains("${"));
            let scope = match tag(block, "scope") {
                Some("test") => Scope::Dev,
                Some("provided") => Scope::Build,
                _ => Scope::Runtime,
            };
            if !group.contains("${") && !artifact.contains("${") {
                report
                    .components
                    .push(declared(group, artifact, version, scope, source));
                found = true;
            }
        }
        rest = &rest[start + end..];
    }
    if !found && text.contains("<dependencies>") {
        report.warnings.push(format!(
            "pom.xml at {source} had no extractable dependencies"
        ));
    }
}

fn gradle_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // implementation("group:artifact:version") / testImplementation 'g:a:v'
        Regex::new(
            r#"(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor)\s*[\( ]\s*["']([\w.\-]+):([\w.\-]+):([\w.\-]+)["']"#,
        )
        .expect("gradle regex compiles")
    })
}

fn scan_gradle(text: &str, source: &str, report: &mut InventoryReport) {
    for caps in gradle_regex().captures_iter(text) {
        let scope = match &caps[1] {
            "testImplementation" | "testRuntimeOnly" => Scope::Dev,
            "compileOnly" | "annotationProcessor" => Scope::Build,
            _ => Scope::Runtime,
        };
        report
            .components
            .push(declared(&caps[2], &caps[3], Some(&caps[4]), scope, source));
    }
}

#[cfg(test)]
mod tests {
    use crate::scan;
    use ovid_repository::{acquire, AcquireOptions, RepositorySource};

    #[test]
    fn pom_and_gradle() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("pom.xml"),
            r#"<project><dependencies>
              <dependency>
                <groupId>org.postgresql</groupId>
                <artifactId>postgresql</artifactId>
                <version>42.7.3</version>
              </dependency>
              <dependency>
                <groupId>org.junit.jupiter</groupId>
                <artifactId>junit-jupiter</artifactId>
                <version>${junit.version}</version>
                <scope>test</scope>
              </dependency>
            </dependencies></project>"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("build.gradle"),
            "dependencies {\n    implementation 'org.apache.kafka:kafka-clients:3.7.0'\n    testImplementation(\"org.mockito:mockito-core:5.11.0\")\n}\n",
        )
        .unwrap();
        let snapshot = acquire(
            &RepositorySource::parse(dir.path().to_str().unwrap(), None),
            &AcquireOptions::new(dir.path().join(".work")),
        )
        .unwrap();
        let report = scan(&snapshot);
        assert!(report.components.iter().any(
            |c| c.name == "org.postgresql:postgresql" && c.version.as_deref() == Some("42.7.3")
        ));
        let junit = report
            .components
            .iter()
            .find(|c| c.name == "org.junit.jupiter:junit-jupiter")
            .unwrap();
        assert!(
            junit.version.is_none(),
            "property placeholder must stay versionless"
        );
        assert_eq!(junit.scope, crate::Scope::Dev);
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "org.apache.kafka:kafka-clients"));
        assert!(report
            .components
            .iter()
            .any(|c| c.name == "org.mockito:mockito-core"));
    }
}
