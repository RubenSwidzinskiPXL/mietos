use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct AppSettings {
    pub model_endpoint: String,
    pub model_name: String,
    pub kali_distro: String,
    pub max_agent_steps: usize,
    pub max_goal_steps: usize,
    pub goal_stall_limit: usize,
    pub memory_path: PathBuf,
    pub tryhackme_api_key: String,
    pub safety_mode: SafetyMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyMode {
    Passive,
    AuthorizedLab,
    InternalAudit,
    FullControl,
}

impl SafetyMode {
    pub const ALL: [Self; 4] = [
        Self::Passive,
        Self::AuthorizedLab,
        Self::InternalAudit,
        Self::FullControl,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Passive => "Passive",
            Self::AuthorizedLab => "Authorized Lab",
            Self::InternalAudit => "Internal Audit",
            Self::FullControl => "Full Control",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Passive => "Passive OSINT, local review, and low-noise setup checks.",
            Self::AuthorizedLab => "CTF/lab workflows with explicit enrolled-target scope.",
            Self::InternalAudit => "Approved company audit workflows with bounded active checks.",
            Self::FullControl => {
                "Advanced operator mode for explicitly approved high-risk workflows."
            }
        }
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            model_endpoint: "http://127.0.0.1:18080/v1/chat/completions".to_string(),
            model_name: "local-cyber-model".to_string(),
            kali_distro: "kali-linux".to_string(),
            max_agent_steps: 8,
            max_goal_steps: 24,
            goal_stall_limit: 4,
            memory_path: default_memory_path(),
            tryhackme_api_key: String::new(),
            safety_mode: SafetyMode::Passive,
        }
    }
}

impl AppSettings {
    pub fn load_or_default() -> Self {
        Self::load_from_path(default_config_path()).unwrap_or_default()
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading settings file {}", path.display()))?;
        let file: SettingsFile = toml::from_str(&text)
            .with_context(|| format!("parsing settings file {}", path.display()))?;
        let mut settings = Self::default();
        file.apply_to(&mut settings);
        Ok(settings)
    }

    pub fn save_to_path(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating settings directory {}", parent.display()))?;
        }
        let file = SettingsFile::from(self);
        let text = toml::to_string_pretty(&file).context("serializing settings file")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing settings file {}", path.display()))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SettingsFile {
    model_endpoint: Option<String>,
    model_name: Option<String>,
    kali_distro: Option<String>,
    max_agent_steps: Option<usize>,
    max_goal_steps: Option<usize>,
    goal_stall_limit: Option<usize>,
    memory_path: Option<PathBuf>,
    safety_mode: Option<SafetyMode>,
}

impl SettingsFile {
    fn apply_to(self, settings: &mut AppSettings) {
        if let Some(value) = self.model_endpoint {
            settings.model_endpoint = value;
        }
        if let Some(value) = self.model_name {
            settings.model_name = value;
        }
        if let Some(value) = self.kali_distro {
            settings.kali_distro = value;
        }
        if let Some(value) = self.max_agent_steps {
            settings.max_agent_steps = value;
        }
        if let Some(value) = self.max_goal_steps {
            settings.max_goal_steps = value;
        }
        if let Some(value) = self.goal_stall_limit {
            settings.goal_stall_limit = value;
        }
        if let Some(value) = self.memory_path {
            settings.memory_path = value;
        }
        if let Some(value) = self.safety_mode {
            settings.safety_mode = value;
        }
    }
}

impl From<&AppSettings> for SettingsFile {
    fn from(settings: &AppSettings) -> Self {
        Self {
            model_endpoint: Some(settings.model_endpoint.clone()),
            model_name: Some(settings.model_name.clone()),
            kali_distro: Some(settings.kali_distro.clone()),
            max_agent_steps: Some(settings.max_agent_steps),
            max_goal_steps: Some(settings.max_goal_steps),
            goal_stall_limit: Some(settings.goal_stall_limit),
            memory_path: Some(settings.memory_path.clone()),
            safety_mode: Some(settings.safety_mode),
        }
    }
}

pub fn default_config_path() -> PathBuf {
    data_dir().join("mietos.toml")
}

fn default_memory_path() -> PathBuf {
    data_dir().join("operator_memory.sqlite3")
}

fn data_dir() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("mietos");
    }
    if let Ok(app_data) = std::env::var("APPDATA") {
        return PathBuf::from(app_data).join("mietos");
    }
    PathBuf::from(".mietos")
}

#[cfg(test)]
mod tests {
    use super::{AppSettings, SafetyMode, default_config_path};

    #[test]
    fn default_settings_use_neutral_model_name_for_public_release() {
        let settings = AppSettings::default();

        assert_eq!(settings.model_name, "local-cyber-model");
    }

    #[test]
    fn default_memory_database_is_not_created_in_repo_root() {
        let settings = AppSettings::default();
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

        assert!(!settings.memory_path.starts_with(manifest));
    }

    #[test]
    fn config_path_uses_mietos_toml_filename() {
        assert_eq!(
            default_config_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("mietos.toml")
        );
    }

    #[test]
    fn settings_load_toml_without_persisting_api_key() {
        let dir = std::env::temp_dir().join(format!("mietos-settings-test-{}", std::process::id()));
        let path = dir.join("mietos.toml");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            &path,
            r#"
model_endpoint = "http://127.0.0.1:9999/v1/chat/completions"
model_name = "test-model"
kali_distro = "kali-test"
max_agent_steps = 3
max_goal_steps = 9
goal_stall_limit = 2
memory_path = "C:\\mietos\\memory.sqlite3"
safety_mode = "internal-audit"
"#,
        )
        .expect("write config");

        let settings = AppSettings::load_from_path(&path).expect("load settings");

        assert_eq!(settings.model_name, "test-model");
        assert_eq!(settings.kali_distro, "kali-test");
        assert_eq!(settings.max_agent_steps, 3);
        assert_eq!(settings.safety_mode, SafetyMode::InternalAudit);
        assert!(settings.tryhackme_api_key.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_save_toml_excludes_tryhackme_api_key() {
        let dir =
            std::env::temp_dir().join(format!("mietos-settings-save-test-{}", std::process::id()));
        let path = dir.join("mietos.toml");
        let _ = std::fs::remove_dir_all(&dir);
        let mut settings = AppSettings::default();
        settings.tryhackme_api_key = "do-not-write".to_string();
        settings.safety_mode = SafetyMode::AuthorizedLab;

        settings.save_to_path(&path).expect("save settings");
        let text = std::fs::read_to_string(&path).expect("read settings");

        assert!(text.contains("safety_mode = \"authorized-lab\""));
        assert!(!text.contains("do-not-write"));
        assert!(!text.contains("tryhackme_api_key"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
