use netcatty_vault::SavedHost;
use serde::Serialize;
use serde_json::Value;

const MAX_VISUAL_SOURCE_TEXT_BYTES: usize = 128;

const HOST_ICON_IDS: &[&str] = &[
    "server",
    "terminal",
    "database",
    "cloud",
    "router",
    "shield",
    "code",
    "box",
    "globe",
    "cpu",
    "hard-drive",
    "network",
    "wifi",
    "lock",
    "key",
    "monitor",
    "container",
    "activity",
    "zap",
    "server-cog",
];

const HOST_ICON_COLOR_IDS: &[&str] = &[
    "blue", "green", "red", "amber", "purple", "cyan", "orange", "slate", "violet", "pink", "rose",
    "lime", "teal", "sky", "indigo", "zinc",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SavedHostVisualView {
    os: Option<String>,
    distro: Option<String>,
    distro_mode: Option<String>,
    manual_distro: Option<String>,
    icon_mode: Option<String>,
    icon_id: Option<String>,
    icon_color_mode: Option<String>,
    icon_color: Option<String>,
    icon_color_custom: Option<String>,
}

impl SavedHostVisualView {
    /// Projects only the bounded, explicitly recognized visual subset of the
    /// flattened legacy Host record. Unknown compatibility metadata never
    /// crosses this renderer boundary.
    pub(crate) fn from_host(host: &SavedHost) -> Self {
        let fields = host.compatibility_fields();
        Self {
            os: exact_token(fields.get("os"), &["linux", "windows", "macos"]),
            distro: canonical_distro(fields.get("distro")),
            distro_mode: exact_token(fields.get("distroMode"), &["auto", "manual"]),
            manual_distro: canonical_distro(fields.get("manualDistro")),
            icon_mode: exact_token(fields.get("iconMode"), &["auto", "custom"]),
            icon_id: exact_token(fields.get("iconId"), HOST_ICON_IDS),
            icon_color_mode: exact_token(fields.get("iconColorMode"), &["auto", "manual"]),
            icon_color: exact_token(fields.get("iconColor"), HOST_ICON_COLOR_IDS),
            icon_color_custom: custom_color(fields.get("iconColorCustom")),
        }
    }
}

fn bounded_text(value: Option<&Value>) -> Option<&str> {
    let value = value?.as_str()?.trim();
    (!value.is_empty()
        && value.len() <= MAX_VISUAL_SOURCE_TEXT_BYTES
        && !value.chars().any(char::is_control))
    .then_some(value)
}

fn exact_token(value: Option<&Value>, allowed: &[&str]) -> Option<String> {
    let value = bounded_text(value)?;
    allowed.contains(&value).then(|| value.to_owned())
}

fn canonical_distro(value: Option<&Value>) -> Option<String> {
    let source = bounded_text(value)?.to_ascii_lowercase();
    let source = source.as_str();
    let distro = if source == "darwin"
        || source == "macos"
        || source == "mac os"
        || source == "mac os x"
        || source.contains("darwin kernel")
        || source.contains("macos")
        || source.contains("mac os")
    {
        "macos"
    } else if source.contains("freebsd") {
        "freebsd"
    } else if source.contains("windows") {
        "windows"
    } else if source.contains("ubuntu") {
        "ubuntu"
    } else if source.contains("debian") {
        "debian"
    } else if source.contains("centos") {
        "centos"
    } else if source.contains("rocky") {
        "rocky"
    } else if source.contains("fedora") {
        "fedora"
    } else if source.contains("arch") || source.contains("manjaro") {
        "arch"
    } else if source.contains("alpine") {
        "alpine"
    } else if source.contains("amzn") || source.contains("amazon") || source.contains("aws") {
        "amazon"
    } else if source.contains("opensuse") || source.contains("suse") || source.contains("sles") {
        "opensuse"
    } else if source.contains("red hat") || source.contains("redhat") || source.contains("rhel") {
        "redhat"
    } else if source.contains("almalinux") {
        "almalinux"
    } else if source.contains("oracle") {
        "oracle"
    } else if source.contains("kali") {
        "kali"
    } else if source.contains("openeuler") || source.contains("open euler") {
        "openeuler"
    } else if source.contains("alinux")
        || source.contains("aliyun")
        || source.contains("alibaba cloud")
    {
        "alinux"
    } else if [
        "cisco", "juniper", "huawei", "h3c", "hpe", "mikrotik", "fortinet", "paloalto", "zyxel",
        "ruijie",
    ]
    .contains(&source)
    {
        source
    } else if source == "linux" || source.contains("linux") {
        "linux"
    } else {
        return None;
    };
    Some(distro.to_owned())
}

fn custom_color(value: Option<&Value>) -> Option<String> {
    let value = bounded_text(value)?;
    let bytes = value.as_bytes();
    (bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit))
        .then(|| value.to_owned())
}

#[cfg(test)]
mod tests {
    use netcatty_vault::{SavedHost, SavedHostDraft};
    use serde_json::{Value, json};

    use super::SavedHostVisualView;

    fn host_with_visual_fields(fields: &[(&str, Value)]) -> SavedHost {
        let mut draft = SavedHostDraft::ssh_password("visual.example.test", "root");
        for (key, value) in fields {
            draft = draft
                .with_compatibility_field(*key, value.clone())
                .expect("safe compatibility field");
        }
        SavedHost::from_draft(draft, 1).expect("saved host")
    }

    #[test]
    fn projects_the_complete_legacy_visual_shape_as_canonical_camel_case() {
        let host = host_with_visual_fields(&[
            ("os", json!("linux")),
            ("distro", json!("Ubuntu 24.04 LTS")),
            ("distroMode", json!("manual")),
            ("manualDistro", json!("Rocky Linux")),
            ("iconMode", json!("custom")),
            ("iconId", json!("database")),
            ("iconColorMode", json!("manual")),
            ("iconColor", json!("violet")),
            ("iconColorCustom", json!("#12Ab34")),
        ]);

        assert_eq!(
            serde_json::to_value(SavedHostVisualView::from_host(&host)).expect("visual JSON"),
            json!({
                "os": "linux",
                "distro": "ubuntu",
                "distroMode": "manual",
                "manualDistro": "rocky",
                "iconMode": "custom",
                "iconId": "database",
                "iconColorMode": "manual",
                "iconColor": "violet",
                "iconColorCustom": "#12Ab34"
            })
        );
    }

    #[test]
    fn rejects_unknown_or_unbounded_compatibility_values_at_the_renderer_boundary() {
        let secret_marker = "visual-secret-must-not-cross";
        let host = host_with_visual_fields(&[
            ("os", json!("plan9")),
            ("distro", json!(secret_marker)),
            ("distroMode", json!("manual\ninvalid")),
            ("manualDistro", json!("x".repeat(129))),
            ("iconMode", json!("custom")),
            ("iconId", json!("database<script>")),
            ("iconColorMode", json!("manual")),
            ("iconColor", json!("visual-secret")),
            ("iconColorCustom", json!("#12345G")),
            ("unrelatedPluginMetadata", json!(secret_marker)),
        ]);

        let encoded = serde_json::to_string(&SavedHostVisualView::from_host(&host))
            .expect("renderer-safe visual JSON");
        assert!(!encoded.contains(secret_marker));
        assert!(!encoded.contains("unrelatedPluginMetadata"));
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).expect("visual JSON"),
            json!({
                "os": null,
                "distro": null,
                "distroMode": null,
                "manualDistro": null,
                "iconMode": "custom",
                "iconId": null,
                "iconColorMode": "manual",
                "iconColor": null,
                "iconColorCustom": null
            })
        );
    }
}
