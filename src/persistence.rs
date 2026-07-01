use crate::config::{save_career_races, save_root, save_tt_races};
use crate::log;
use serde_json::Value;
use std::fs::{self, File};
use std::io::Write;

pub fn save_race_info(mut race_info: Value) {
    let top_level_keys = race_info.as_object().map(|m| m.len()).unwrap_or(0);
    log!(
        "[RaceInfo] save_race_info called: type={}, top_level_keys={}",
        value_kind(&race_info),
        top_level_keys
    );

    normalize_field_names(&mut race_info);

    if let Some(sim_data) = race_info.get("simDataBase64") {
        log!(
            "[RaceInfo] SimDataBase64 present: type={}, is_null={}",
            value_kind(sim_data),
            sim_data.is_null()
        );
        if sim_data.is_null() {
            log!("[RaceInfo] Skipped saving: simDataBase64 is null.");
            return;
        }
    } else {
        log!("[RaceInfo] simDataBase64 key missing from converted RaceInfo JSON.");
    }

    if let Value::Object(ref mut map) = race_info {
        map.insert(
            "horseACT_version".to_string(),
            Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );
    }

    let now = chrono::Local::now();
    let date_str = now.format("%Y%m%d").to_string();

    let mut filename = format!("{}.json", now.format("%Y%m%d_%H%M%S_%3f"));

    if let Some(horses) = race_info.get("raceHorse").and_then(|v| v.as_array()) {
        log!("[RaceInfo] RaceHorse array length: {}", horses.len());
        let winner_opt = horses
            .iter()
            .find(|h| h.get("finishOrder").and_then(|v| v.as_i64()) == Some(0));

        if let Some(winner) = winner_opt {
            let name = winner
                .get("charaName")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");

            let raw_time = winner
                .get("finishTimeRaw")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            let safe_name: String = name
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == ' ' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();

            filename = format!("{}-{:.4}s-{}.json", safe_name.trim(), raw_time, date_str);
            log!(
                "[RaceInfo] Winner detected: name='{}', raw_time={:.4}, filename={}",
                name,
                raw_time,
                filename
            );
        } else {
            log!("[RaceInfo] No winner found with FinishOrder == 0.");
        }
    } else {
        log!("[RaceInfo] RaceHorse key missing or not an array.");
    }

    let race_type = race_info.get("raceType").and_then(|v| v.as_str());
    let folder = match race_type {
        Some("RoomMatch") => "Room match",
        Some("Champions") => "Champions meeting",
        Some("Single") => "Career",
        Some("Practice") => "Practice room",
        _ => "Other",
    };
    log!(
        "[RaceInfo] RaceType={:?}, selected_folder={}",
        race_type,
        folder
    );

    if folder == "Career" && !save_career_races() {
        log!("[RaceInfo] Skipped saving Career race because saveCareerRaces is disabled.");
        return;
    }

    let dir = save_root().join(folder);
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[RaceInfo] Failed to create dir {:?}: {}", dir, e);
            return;
        }
    }

    let path = dir.join(filename);
    log!(
        "[RaceInfo] Attempting to save race JSON to: {}",
        path.display()
    );

    match File::create(&path) {
        Ok(mut f) => match serde_json::to_string_pretty(&race_info) {
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
        },
        Err(e) => {
            log!("[RaceInfo] Failed to create file: {}", e);
        }
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn normalize_field_names(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                normalize_field_names(item);
            }
        }
        Value::Object(map) => {
            let old = std::mem::take(map);
            for (key, mut child) in old {
                normalize_field_names(&mut child);
                map.insert(normalize_field_name(&key), child);
            }
        }
        _ => {}
    }
}

fn normalize_field_name(raw_name: &str) -> String {
    let mut name = raw_name.trim_start_matches('_');
    if name.is_empty() {
        return String::new();
    }

    if let Some(backing_name) = name
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix(">k__BackingField"))
    {
        name = backing_name.trim_start_matches('_');
        if name.is_empty() {
            return String::new();
        }
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };

    first.to_lowercase().chain(chars).collect()
}

pub fn save_team_trial_result(mut response: Value) {
    if !save_tt_races() {
        log!("[TeamTrials] Skipped saving because saveTTRaces is disabled.");
        return;
    }

    if let Value::Object(ref mut map) = response {
        map.insert(
            "horseACT_version".to_string(),
            Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );
    }

    let now = chrono::Local::now();
    let filename = format!("TT-{}.json", now.format("%Y%m%d_%H%M%S_%3f"));
    let dir = save_root().join("Team trials");

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[TeamTrials] Failed to create dir {:?}: {}", dir, e);
            return;
        }
    }

    let path = dir.join(filename);
    match File::create(&path) {
        Ok(mut f) => match serde_json::to_string_pretty(&response) {
            Ok(json_str) => {
                if let Err(e) = write!(f, "{}", json_str) {
                    log!("[TeamTrials] Failed to write JSON: {}", e);
                } else {
                    log!("[TeamTrials] Saved to: {}", path.display());
                }
            }
            Err(e) => {
                log!("[TeamTrials] Failed to serialize JSON: {}", e);
            }
        },
        Err(e) => {
            log!("[TeamTrials] Failed to create file: {}", e);
        }
    }
}

pub fn save_debug_response(label: &str, mut response: Value) {
    if let Value::Object(ref mut map) = response {
        map.insert(
            "horseACT_version".to_string(),
            Value::String(env!("CARGO_PKG_VERSION").to_string()),
        );
        map.insert(
            "horseACT_debug_label".to_string(),
            Value::String(label.to_string()),
        );
    }

    let key_count = response.as_object().map(|m| m.len()).unwrap_or(0);
    log!(
        "[CommonResponseProbe] Saving {}: type={}, top_level_keys={}",
        label,
        value_kind(&response),
        key_count
    );

    let now = chrono::Local::now();
    let safe_label: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let filename = format!("{}-{}.json", safe_label, now.format("%Y%m%d_%H%M%S_%3f"));
    let dir = save_root().join("API responses");

    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            log!("[CommonResponseProbe] Failed to create dir {:?}: {}", dir, e);
            return;
        }
    }

    let path = dir.join(filename);
    match File::create(&path) {
        Ok(mut f) => match serde_json::to_string_pretty(&response) {
            Ok(json_str) => {
                if let Err(e) = write!(f, "{}", json_str) {
                    log!("[CommonResponseProbe] Failed to write JSON: {}", e);
                } else {
                    log!("[CommonResponseProbe] Saved to: {}", path.display());
                }
            }
            Err(e) => {
                log!("[CommonResponseProbe] Failed to serialize JSON: {}", e);
            }
        },
        Err(e) => {
            log!("[CommonResponseProbe] Failed to create file: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{normalize_field_name, normalize_field_names};
    use serde_json::json;

    #[test]
    fn normalizes_il2cpp_field_names() {
        assert_eq!(normalize_field_name("_fieldName"), "fieldName");
        assert_eq!(
            normalize_field_name("<SimDataBase64>k__BackingField"),
            "simDataBase64"
        );
        assert_eq!(
            normalize_field_name("<_charaName>k__BackingField"),
            "charaName"
        );
        assert_eq!(normalize_field_name("FinishTimeRaw"), "finishTimeRaw");
        assert_eq!(normalize_field_name(""), "");
    }

    #[test]
    fn normalizes_nested_json_object_keys() {
        let mut value = json!({
            "<RaceHorse>k__BackingField": [
                {
                    "<charaName>k__BackingField": "Seiun Sky",
                    "FinishOrder": 0
                }
            ],
            "_privateValue": true
        });

        normalize_field_names(&mut value);

        assert_eq!(value["raceHorse"][0]["charaName"], "Seiun Sky");
        assert_eq!(value["raceHorse"][0]["finishOrder"], 0);
        assert_eq!(value["privateValue"], true);
    }
}

pub fn save_veteran_data(list_data: Value) {
    if !list_data.is_array() {
        log!(
            "[Veteran] Warning: Data is not an array, got: {:?}",
            list_data
        );
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
        Ok(mut f) => match serde_json::to_string_pretty(&list_data) {
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
        },
        Err(e) => {
            log!("[Veteran] Failed to create file: {}", e);
        }
    }
}
