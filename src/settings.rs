use std::path::PathBuf;

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
        }
    }
}

fn default_memory_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("mietos")
            .join("operator_memory.sqlite3");
    }
    if let Ok(app_data) = std::env::var("APPDATA") {
        return PathBuf::from(app_data)
            .join("mietos")
            .join("operator_memory.sqlite3");
    }
    PathBuf::from(".mietos").join("operator_memory.sqlite3")
}

#[cfg(test)]
mod tests {
    use super::AppSettings;

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
}
