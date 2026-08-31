use serde::Serialize;

/// Basic proof that the desktop UI is talking to the new Rust backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendStatus {
    pub app_version: String,
    pub runtime: String,
    pub operating_system: String,
    pub architecture: String,
    pub process_id: u32,
}

impl BackendStatus {
    #[must_use]
    pub fn current(app_version: impl Into<String>) -> Self {
        Self {
            app_version: app_version.into(),
            runtime: "tauri-rust".to_owned(),
            operating_system: std::env::consts::OS.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            process_id: std::process::id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BackendStatus;

    #[test]
    fn status_uses_the_requested_app_version() {
        let status = BackendStatus::current("0.1.0-test");

        assert_eq!(status.app_version, "0.1.0-test");
        assert_eq!(status.runtime, "tauri-rust");
        assert!(status.process_id > 0);
    }
}
