use serde_json::Value;
use std::sync::LazyLock;

/// Maps W3C Design Token names to the CSS custom property names used in PAGE_CSS.
fn token_to_css_var(name: &str) -> Option<&'static str> {
    match name {
        "primary" => Some("--link"),
        "background" => Some("--bg"),
        "surface" => Some("--card"),
        "text" => Some("--text"),
        "muted" => Some("--muted"),
        "border" => Some("--border"),
        _ => None,
    }
}

/// Emits CSS declarations for a token group (e.g. `color` or `color-dark`).
fn declarations_from_group(group: &Value) -> String {
    let obj = match group.as_object() {
        Some(o) => o,
        None => return String::new(),
    };
    let mut decls = String::new();
    for (name, token) in obj {
        if let (Some(var), Some(value)) = (
            token_to_css_var(name),
            token.get("$value").and_then(|v| v.as_str()),
        ) {
            decls.push_str(var);
            decls.push(':');
            decls.push_str(value);
            decls.push(';');
        }
    }
    decls
}

/// Loads a W3C Design Tokens JSON file and compiles it to CSS custom property overrides.
///
/// - `color` group produces `:root { ... }`
/// - `color-dark` group produces `@media (prefers-color-scheme: dark) { :root { ... } }`
///
/// Returns an empty string if the path is empty or on any error (with a warning logged).
pub fn load_theme_css(config: &crate::config::Config) -> String {
    let path = &config.branding.theme_tokens_path;
    if path.is_empty() {
        return String::new();
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(path, "failed to load theme tokens: {e}");
            return String::new();
        }
    };
    let doc: Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(path, "failed to parse theme tokens JSON: {e}");
            return String::new();
        }
    };

    let mut css = String::new();

    if let Some(light) = doc.get("color") {
        let decls = declarations_from_group(light);
        if !decls.is_empty() {
            css.push_str(":root{");
            css.push_str(&decls);
            css.push('}');
        }
    }

    if let Some(dark) = doc.get("color-dark") {
        let decls = declarations_from_group(dark);
        if !decls.is_empty() {
            css.push_str("@media(prefers-color-scheme:dark){:root{");
            css.push_str(&decls);
            css.push_str("}}");
        }
    }

    // Defense in depth: strip </style> sequences even though token values come from
    // an operator-controlled JSON file. This CSS ends up inside a <style> tag.
    static STYLE_TAG_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?i)</\s*style").unwrap());
    css = STYLE_TAG_RE.replace_all(&css, "").to_string();

    css
}
