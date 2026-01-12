use std::fs::{self, File};
use std::io::Write;
use serde_json::Value;
use crate::config::save_root;
use crate::log;
use crate::reflection::CAPTURED_ENUMS;

pub fn save_race_info(race_info: Value) {
    let now = chrono::Local::now();
    let date_str = now.format("%Y%m%d").to_string();
    
    let mut filename = format!("{}.json", now.format("%Y%m%d_%H%M%S_%3f"));

    if let Some(horses) = race_info.get("<RaceHorse>k__BackingField").and_then(|v| v.as_array()) {
        let winner_opt = horses.iter().find(|h| {
            h.get("FinishOrder").and_then(|v| v.as_i64()) == Some(0)
        });

        if let Some(winner) = winner_opt {
            let name = winner
                .get("<charaName>k__BackingField")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");

            let raw_time = winner
                .get("FinishTimeRaw")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            let safe_name: String = name
                .chars()
                .map(|c| if c.is_alphanumeric() || c == ' ' || c == '-' { c } else { '_' })
                .collect();

            filename = format!("{}-{:.4}s-{}.json", safe_name.trim(), raw_time, date_str);
        }
    }

    let folder = match race_info.get("<RaceType>k__BackingField").and_then(|v| v.as_str()) {
        Some("RoomMatch") => "Room match",
        Some("Champions") => "Champions meeting",
        Some("Single") => "Career",
        Some("Practice") => "Practice room",
        _ => "Other",
    };

    let dir = save_root().join(folder);
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[RaceInfo] Failed to create dir {:?}: {}", dir, e);
            return;
        }
    }

    let path = dir.join(filename);

    match File::create(&path) {
        Ok(mut f) => {
            match serde_json::to_string_pretty(&race_info) {
                Ok(json_str) => {
                    if let Err(e) = write!(f, "{}", json_str) {
                        log!("[RaceInfo] Failed to write JSON: {}", e);
                    } else {
                        log!("[RaceInfo] Saved to: {}", path.display());
                    }
                }
                Err(e) => {
                    log!("[RaceInfo] Failed to serialize JSON: {}", e);
                }
            }
        }
        Err(e) => {
            log!("[RaceInfo] Failed to create file: {}", e);
        }
    }
}

pub fn save_enums() {
    let guard = CAPTURED_ENUMS.lock().unwrap();
    if let Some(map) = guard.as_ref() {
        let path = save_root().join("Enums.json");
        let final_json = Value::Object(map.clone());

        match File::create(&path) {
            Ok(mut f) => {
                if let Ok(json_str) = serde_json::to_string_pretty(&final_json) {
                    let _ = write!(f, "{}", json_str);
                    log!("[Enums] Updated Enums.json with {} types.", map.len());
                }
            }
            Err(e) => {
                log!("[Enums] Failed to save Enums.json: {}", e);
            }
        }
    }
}

pub fn save_static_data(filename: &str, data: Value) {
    let path = save_root().join(format!("{}.json", filename));

    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
        if let Ok(mut f) = File::create(&path) {
            let _ = write!(f, "{}", json_str);
            log!("[{}] Saved to: {}", filename, path.display());
        }
    }
}

pub fn save_veteran_data(list_data: Value) {
    if !list_data.is_array() {
        log!("[Veteran] Warning: Data is not an array, got: {:?}", list_data);
        return;
    }

    if let Value::Array(ref arr) = list_data {
        if arr.is_empty() {
            log!("[Veteran] No veteran characters to save (empty list)");
            return;
        }
        log!("[Veteran] Saving {} veteran character(s)", arr.len());
    }

    let path = save_root().join("veterans.json");

    match File::create(&path) {
        Ok(mut f) => {
            match serde_json::to_string_pretty(&list_data) {
                Ok(json_str) => {
                    if let Err(e) = write!(f, "{}", json_str) {
                        log!("[Veteran] Failed to write JSON: {}", e);
                    } else {
                        log!("[Veteran] Saved to: {}", path.display());
                    }
                }
                Err(e) => {
                    log!("[Veteran] Failed to serialize JSON: {}", e);
                }
            }
        }
        Err(e) => {
            log!("[Veteran] Failed to create file: {}", e);
        }
    }
}