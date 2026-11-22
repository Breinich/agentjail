//! JSON Schema validation against the embedded canonical profile schema.
//!
//! `schema/profile.schema.json` is compiled into the binary with `include_str!`,
//! so a installed `agentjail` cannot run against a stale or missing copy, and CI
//! fails at build time if the file disappears. The typed model in
//! `profile.rs` is validated against it, which is what keeps the prose
//! reference, the machine-readable document, and the implementation aligned.

/// The canonical schema, embedded at compile time.
pub const PROFILE_SCHEMA_JSON: &str = include_str!("../../../schema/profile.schema.json");

/// Validate a parsed TOML document against the profile schema.
///
/// Errors are returned as `path: message`, with the JSON pointer rendered in
/// the same dotted form the semantic checks use (`network.egress[0].port`).
pub fn validate(value: &toml::Value) -> Vec<String> {
    let schema: serde_json::Value = match serde_json::from_str(PROFILE_SCHEMA_JSON) {
        Ok(schema) => schema,
        Err(error) => return vec![format!("profile schema is not valid JSON: {error}")],
    };
    let instance: serde_json::Value = match serde_json::to_value(value) {
        Ok(instance) => instance,
        Err(error) => return vec![format!("profile cannot be read as JSON: {error}")],
    };
    let validator = match jsonschema::validator_for(&schema) {
        Ok(validator) => validator,
        Err(error) => return vec![format!("profile schema is unusable: {error}")],
    };
    validator
        .iter_errors(&instance)
        .map(|error| {
            let path = friendly_path(&error.instance_path().to_string());
            format!("{path}: {error}")
        })
        .collect()
}

/// The schema as a JSON value, for tests and tooling.
pub fn schema_document() -> serde_json::Value {
    serde_json::from_str(PROFILE_SCHEMA_JSON).expect("embedded profile schema is valid JSON")
}

/// Turn a JSON pointer (`/network/egress/0/port`) into `network.egress[0].port`.
fn friendly_path(raw: &str) -> String {
    if raw.is_empty() {
        return "<root>".to_string();
    }
    let mut out = String::new();
    for segment in raw.split('/').skip(1) {
        let token = segment.replace("~1", "/").replace("~0", "~");
        if !token.is_empty() && token.chars().all(|c| c.is_ascii_digit()) {
            out.push('[');
            out.push_str(&token);
            out.push(']');
        } else {
            if !out.is_empty() {
                out.push('.');
            }
            out.push_str(&token);
        }
    }
    if out.is_empty() {
        "<root>".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn valid_document() -> toml::Value {
        toml::from_str(
            r#"
version = 1
workdir = "/work"
home = "/home/agent"
[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
[network]
mode = "none"
dns = "none"
[agent]
command = "bash"
"#,
        )
        .expect("valid TOML")
    }

    #[test]
    fn valid_document_has_no_schema_errors() {
        assert!(validate(&valid_document()).is_empty());
    }

    #[test]
    fn missing_network_is_a_schema_error() {
        let mut document = valid_document();
        document.as_table_mut().unwrap().remove("network");
        let errors = validate(&document);
        assert!(
            errors.iter().any(|error| error.contains("network")),
            "{errors:#?}"
        );
    }

    #[test]
    fn missing_dns_is_a_schema_error() {
        let document: toml::Value = toml::from_str(
            r#"
version = 1
workdir = "/work"
home = "/home/agent"
[image]
name = "localhost/agentjail-base:1"
digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
[network]
mode = "none"
[agent]
command = "bash"
"#,
        )
        .expect("TOML");
        let errors = validate(&document);
        assert!(
            errors.iter().any(|error| error.contains("dns")),
            "{errors:#?}"
        );
    }

    #[test]
    fn unknown_property_is_a_schema_error() {
        let mut document = valid_document();
        document
            .as_table_mut()
            .unwrap()
            .insert("proxy".to_string(), toml::Value::String("x".into()));
        let errors = validate(&document);
        assert!(
            errors.iter().any(|error| error.contains("proxy")),
            "{errors:#?}"
        );
    }

    #[test]
    fn path_rendering_is_dotted() {
        assert_eq!(friendly_path(""), "<root>");
        assert_eq!(friendly_path("/a/b"), "a.b");
        assert_eq!(friendly_path("/a/0/b"), "a[0].b");
        assert_eq!(friendly_path("/a~1b"), "a/b");
    }

    #[test]
    fn embedded_schema_covers_the_required_areas() {
        let document = schema_document();
        let properties = document["properties"].as_object().expect("properties");
        let expected: BTreeSet<&str> = [
            "version",
            "description",
            "image",
            "workdir",
            "home",
            "mounts",
            "env",
            "secrets",
            "network",
            "resources",
            "agent",
        ]
        .into_iter()
        .collect();
        let actual: BTreeSet<&str> = properties.keys().map(String::as_str).collect();
        assert_eq!(actual, expected);

        let required: BTreeSet<&str> = document["required"]
            .as_array()
            .expect("required")
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(
            required,
            BTreeSet::from(["agent", "home", "image", "network", "version", "workdir"])
        );

        let defs = &document["$defs"];
        assert_eq!(defs["network"]["required"].as_array().unwrap().len(), 2);
        assert_eq!(defs["secret"]["additionalProperties"], false);
        assert!(defs["resources"]["properties"]["disk"].is_object());
        assert!(defs["resources"]["properties"]["tmpfs"].is_object());
    }

    #[test]
    fn schema_does_not_make_network_or_home_optional() {
        let document = schema_document();
        let required = document["required"].as_array().expect("required");
        assert!(required.iter().any(|value| value == "network"));
        assert!(required.iter().any(|value| value == "home"));
        let network_required = document["$defs"]["network"]["required"].as_array().unwrap();
        assert!(network_required.iter().any(|value| value == "mode"));
        assert!(network_required.iter().any(|value| value == "dns"));
    }

    #[test]
    fn egress_defaults_to_nothing() {
        let document = schema_document();
        assert_eq!(
            document["$defs"]["network"]["properties"]["egress"]["default"],
            serde_json::json!([])
        );
    }
}
