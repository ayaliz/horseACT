use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{create_dir_all, read_to_string, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    sync::OnceLock,
};

static SAVE_ROOT: OnceLock<PathBuf> = OnceLock::new();
static API_KEY: OnceLock<String> = OnceLock::new();
static SERVER_URL: OnceLock<String> = OnceLock::new();
static FIELD_BLACKLIST: OnceLock<Vec<String>> = OnceLock::new();
static SAVE_CAREER_RACES: OnceLock<bool> = OnceLock::new();
static SAVE_TT_RACES: OnceLock<bool> = OnceLock::new();
static LOG_MUTEX: Mutex<()> = Mutex::new(());

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
    #[serde(rename = "saveCareerRaces", default = "default_save_career_races")]
    save_career_races: bool,
    #[serde(rename = "saveTTRaces", default = "default_save_tt_races")]
    save_tt_races: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            output_path: Some("%USERPROFILE%\\Documents".to_string()),
            api_key: String::new(),
            server_url: String::new(),
            field_blacklist: default_field_blacklist(),
            save_career_races: default_save_career_races(),
            save_tt_races: default_save_tt_races(),
        }
    }
}

fn default_save_career_races() -> bool {
    true
}

fn default_save_tt_races() -> bool {
    false
}

#[derive(Deserialize, Serialize, Clone)]
pub struct EndpointConfig {
    pub name: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default, rename = "sensitiveFields")]
    pub sensitive_fields: Vec<String>,
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
    FIELD_BLACKLIST
        .get()
        .expect("field blacklist not initialized")
}

pub fn save_career_races() -> bool {
    *SAVE_CAREER_RACES
        .get()
        .expect("save career races flag not initialized")
}

pub fn save_tt_races() -> bool {
    *SAVE_TT_RACES
        .get()
        .expect("save TT races flag not initialized")
}

pub fn is_field_blacklisted(name: &str, sensitive_fields: &[String]) -> bool {
    if sensitive_fields.iter().any(|pattern| name == pattern) {
        return false;
    }
    field_blacklist().iter().any(|pattern| name == pattern)
}

pub fn init_paths() -> Result<(), String> {
    let plugin_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    debug_log_internal(&format!("[Config] plugin_dir={}", plugin_dir.display()));

    let cfg_dir = plugin_dir.join("hachimi");
    if let Err(e) = create_dir_all(&cfg_dir) {
        return Err(format!("create hachimi dir: {}", e));
    }

    let cfg_path = cfg_dir.join("horseACTConfig.json");
    debug_log_internal(&format!("[Config] config_path={}", cfg_path.display()));

    let cfg: Config = if cfg_path.exists() {
        debug_log_internal("[Config] Loading existing config.");
        read_to_string(&cfg_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        debug_log_internal("[Config] Config not found; writing defaults.");
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
    debug_log_internal(&format!(
        "[Config] outputPath={:?}, resolved_save_root={}",
        cfg.output_path,
        saved.display()
    ));
    debug_log_internal(&format!(
        "[Config] saveCareerRaces={}, saveTTRaces={}, fieldBlacklistCount={}",
        cfg.save_career_races,
        cfg.save_tt_races,
        cfg.field_blacklist.len()
    ));

    let sub_dirs = [
        "Room match",
        "Champions meeting",
        "Practice room",
        "Career",
        "Team trials",
        "Other",
    ];

    for d in sub_dirs {
        let p = saved.join(d);
        if let Err(e) = create_dir_all(&p) {
            return Err(format!("create {} dir: {}", d, e));
        }
    }

    SAVE_ROOT
        .set(saved)
        .map_err(|_| "SAVE_ROOT was already initialized".to_string())?;
    let _ = API_KEY.set(cfg.api_key);
    let _ = SERVER_URL.set(cfg.server_url);
    let _ = FIELD_BLACKLIST.set(cfg.field_blacklist);
    let _ = SAVE_CAREER_RACES.set(cfg.save_career_races);
    let _ = SAVE_TT_RACES.set(cfg.save_tt_races);
    Ok(())
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::config::debug_log_internal(&format!($($arg)*));
    };
}

pub fn debug_log_internal(msg: &str) {
    let _guard = LOG_MUTEX.lock().ok();

    let plugin_dir = env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let log_dir = plugin_dir.join("hachimi");
    let _ = create_dir_all(&log_dir);
    let log_path = log_dir.join("horseACT.log");

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let now = chrono::Local::now();
        let _ = writeln!(file, "{} {}", now.format("%Y-%m-%d %H:%M:%S%.3f"), msg);
    }
}
