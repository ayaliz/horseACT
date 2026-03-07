use std::fs::File;
use std::io::Write;
use std::sync::OnceLock;
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde_json::{Map, Value};
use crate::config::{api_key, server_url, save_root, EndpointConfig};
use crate::log;

type HmacSha256 = Hmac<Sha256>;

static ENDPOINT_CONFIGS: OnceLock<Vec<EndpointConfig>> = OnceLock::new();

pub fn store_endpoint_configs(configs: Vec<EndpointConfig>) {
    let _ = ENDPOINT_CONFIGS.set(configs);
}

pub fn endpoint_configs() -> &'static [EndpointConfig] {
    ENDPOINT_CONFIGS.get().map(|v| v.as_slice()).unwrap_or(&[])
}

pub fn fetch_endpoint_config() -> Result<Vec<EndpointConfig>, String> {
    let sv = server_url();
    if sv.is_empty() {
        return Err("No server URL configured".to_string());
    }
    let url = format!("{}/config", sv.trim_end_matches('/'));
    let resp = ureq::get(&url)
        .set("X-API-Key", api_key())
        .call()
        .map_err(|e| format!("Request failed: {}", e))?;
    let body = resp.into_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;
    serde_json::from_str::<Vec<EndpointConfig>>(&body)
        .map_err(|e| format!("Failed to parse response: {}", e))
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex character in HORSEACT_HMAC_KEY"),
    }
}

const fn decode_key(s: &str) -> [u8; 32] {
    let s = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(s[i * 2]) << 4) | hex_nibble(s[i * 2 + 1]);
        i += 1;
    }
    out
}

const HMAC_KEY: [u8; 32] = decode_key(env!("HORSEACT_HMAC_KEY"));

pub fn dispatch(endpoint: &str, data: Value) {
    let path = save_root()
        .join("API responses")
        .join(format!("{}.json", endpoint));

    if let Ok(json_str) = serde_json::to_string_pretty(&data) {
        if let Ok(mut f) = File::create(&path) {
            let _ = write!(f, "{}", json_str);
        }
        log!("[{}] Saved to: {}", endpoint, path.display());
    }

    let sv = server_url();
    if sv.is_empty() {
        return;
    }

    let fields: Vec<String> = endpoint_configs().iter()
        .find(|e| e.name == endpoint)
        .map(|e| e.fields.clone())
        .unwrap_or_default();

    let server_url_owned = sv.to_string();
    let api_key_owned = api_key().to_string();
    let endpoint_owned = endpoint.to_string();
    let payload = extract_fields(&data, &fields);

    std::thread::spawn(move || {
        send(&server_url_owned, &api_key_owned, &endpoint_owned, &payload);
    });
}

fn extract_fields(data: &Value, fields: &[String]) -> Value {
    if fields.is_empty() {
        return data.clone();
    }
    let mut result = Map::new();
    for field in fields {
        let path: Vec<&str> = field.split('.').collect();
        apply_field_spec(data, &mut result, &path);
    }
    Value::Object(result)
}

fn apply_field_spec(src: &Value, dst: &mut Map<String, Value>, path: &[&str]) {
    if path.is_empty() { return; }
    let key = path[0];
    let rest = &path[1..];
    let child = match src.get(key) {
        Some(v) => v,
        None => return,
    };
    if rest.is_empty() {
        dst.insert(key.to_string(), child.clone());
        return;
    }
    match child {
        Value::Array(arr) => {
            let items: Vec<Value> = arr.iter().map(|elem| {
                let mut inner = Map::new();
                apply_field_spec(elem, &mut inner, rest);
                Value::Object(inner)
            }).collect();
            if let Some(Value::Array(existing)) = dst.get_mut(key) {
                for (ex, new) in existing.iter_mut().zip(items.into_iter()) {
                    if let (Value::Object(ex_map), Value::Object(new_map)) = (ex, new) {
                        ex_map.extend(new_map);
                    }
                }
            } else {
                dst.insert(key.to_string(), Value::Array(items));
            }
        }
        Value::Object(_) => {
            let entry = dst
                .entry(key.to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(ref mut nested) = entry {
                apply_field_spec(child, nested, rest);
            }
        }
        _ => {}
    }
}

fn sign(data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(&HMAC_KEY).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

fn send(server_url: &str, api_key: &str, endpoint: &str, data: &Value) {
    let json_bytes = match serde_json::to_vec(data) {
        Ok(b) => b,
        Err(e) => {
            log!("[API] Failed to serialize {}: {}", endpoint, e);
            return;
        }
    };

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if let Err(e) = encoder.write_all(&json_bytes) {
        log!("[API] Failed to compress {}: {}", endpoint, e);
        return;
    }
    let compressed = match encoder.finish() {
        Ok(c) => c,
        Err(e) => {
            log!("[API] Failed to finalize compression for {}: {}", endpoint, e);
            return;
        }
    };

    let signature = sign(&compressed);
    let url = format!("{}/ingest/{}", server_url.trim_end_matches('/'), endpoint);

    match ureq::post(&url)
        .set("X-API-Key", api_key)
        .set("X-Signature", &signature)
        .set("Content-Encoding", "gzip")
        .set("Content-Type", "application/json")
        .send_bytes(&compressed)
    {
        Ok(resp) => {
            log!("[API] {} -> server: {}", endpoint, resp.status());
        }
        Err(e) => {
            log!("[API] Failed to send {}: {}", endpoint, e);
        }
    }
}
