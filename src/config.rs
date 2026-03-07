use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::CString,
    fs::{create_dir_all, read_to_string, File},
    io::Write,
    path::{Path, PathBuf},
    sync::OnceLock,
};

static SAVE_ROOT: OnceLock<PathBuf> = OnceLock::new();
static HACHIMI_DIR: OnceLock<PathBuf> = OnceLock::new();
static API_KEY: OnceLock<String> = OnceLock::new();
static SERVER_URL: OnceLock<String> = OnceLock::new();
static FIELD_BLACKLIST: OnceLock<Vec<String>> = OnceLock::new();

fn default_field_blacklist() -> Vec<String> {
    vec![
        "_ownerViewerId".to_string(),
		"_viewerId".to_string(),
		"owner_viewer_id".to_string(),
        "viewer_id".to_string(),
        "<SimData>k__BackingField".to_string(),
        "<SimReader>k__BackingField".to_string(),
        "CreateTime".to_string(),
		"succession_history_array".to_string(),
    ]
}

#[derive(Deserialize, Serialize)]
struct Config {
    #[serde(rename = "outputPath")]
    output_path: Option<String>,
    #[serde(rename = "apiKey", default)]
    api_key: String,
    #[serde(rename = "serverUrl", default)]
    server_url: String,
    #[serde(rename = "fieldBlacklist", default = "default_field_blacklist")]
    field_blacklist: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            output_path: Some("%USERPROFILE%\\Documents".to_string()),
            api_key: String::new(),
            server_url: String::new(),
            field_blacklist: default_field_blacklist(),
        }
    }
}

#[derive(Deserialize, Serialize, Clone)]
pub struct EndpointConfig {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<String>,
}

pub fn api_key() -> &'static str {
    API_KEY.get().map(|s| s.as_str()).unwrap_or("")
}

pub fn server_url() -> &'static str {
    SERVER_URL.get().map(|s| s.as_str()).unwrap_or("")
}

pub fn save_root() -> &'static PathBuf {
    SAVE_ROOT.get().expect("save root not initialized")
}

pub fn field_blacklist() -> &'static Vec<String> {
    FIELD_BLACKLIST.get().expect("field blacklist not initialized")
}

pub fn is_field_blacklisted(name: &str) -> bool {
    field_blacklist().iter().any(|pattern| name == pattern)
}

pub fn init_paths() -> Result<(), String> {
    let plugin_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));

    let cfg_dir = plugin_dir.join("hachimi");
    if let Err(e) = create_dir_all(&cfg_dir) {
        return Err(format!("create hachimi dir: {}", e));
    }

    let _ = HACHIMI_DIR.set(cfg_dir.clone());

    let cfg_path = cfg_dir.join("horseACTConfig.json");

    let cfg: Config = if cfg_path.exists() {
        read_to_string(&cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        Config::default()
    };

    // Always re-write config to add new fields and remove obsolete ones
    if let Ok(mut f) = File::create(&cfg_path) {
        let _ = writeln!(
            f,
            "{}",
            serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into())
        );
    }

    let resolved_root = match cfg.output_path.as_deref() {
        Some(p) if !p.trim().is_empty() => {
            let path_str = p.trim();
            let expanded_path = if let Ok(home) = env::var("USERPROFILE") {
                path_str.replace("%USERPROFILE%", &home)
            } else {
                path_str.to_string()
            };
            let path = Path::new(&expanded_path);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                plugin_dir.join(path)
            }
        }
        _ => plugin_dir.clone(),
    };

    let saved = resolved_root.join("Saved races");

    let sub_dirs = [
        "Room match",
        "Champions meeting",
        "Practice room",
        "Career",
        "Other",
        "API responses",
    ];

    for d in sub_dirs {
        let p = saved.join(d);
        if let Err(e) = create_dir_all(&p) {
            return Err(format!("create {} dir: {}", d, e));
        }
    }

    SAVE_ROOT.set(saved).map_err(|_| "SAVE_ROOT was already initialized".to_string())?;
    let _ = API_KEY.set(cfg.api_key);
    let _ = SERVER_URL.set(cfg.server_url);
    let _ = FIELD_BLACKLIST.set(cfg.field_blacklist);
    Ok(())
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::config::debug_log_internal(&format!($($arg)*));
    };
}

pub fn debug_log_internal(msg: &str) {
    if let Ok(message) = CString::new(msg) {
        unsafe {
            (crate::plugin_api::vtable().log)(3, c"horseACT".as_ptr(), message.as_ptr());
        }
    }
}
