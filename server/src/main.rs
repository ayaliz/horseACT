use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    body::Bytes,
    Json,
    Router,
};
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::Read;
use std::sync::Arc;
use tokio::fs;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
struct AppState {
    api_key: String,
    hmac_key: Vec<u8>,
    output_dir: String,
    endpoint_config: serde_json::Value,
}

fn verify_signature(hmac_key: &[u8], body: &[u8], provided_hex: &str) -> bool {
    let Ok(provided_bytes) = hex::decode(provided_hex) else { return false; };
    let Ok(mut mac) = HmacSha256::new_from_slice(hmac_key) else { return false; };
    mac.update(body);
    mac.verify_slice(&provided_bytes).is_ok()
}

fn check_api_key(state: &AppState, headers: &HeaderMap, label: &str) -> bool {
    let provided = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if provided != state.api_key {
        eprintln!("[{}] Rejected: invalid API key", label);
        return false;
    }
    true
}

async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_api_key(&state, &headers, "config") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(state.endpoint_config.clone()))
}

async fn ingest(
    Path(endpoint): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    if !check_api_key(&state, &headers, &endpoint) {
        return StatusCode::UNAUTHORIZED;
    }

    let provided_sig = headers
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_signature(&state.hmac_key, &body, provided_sig) {
        eprintln!("[{}] Rejected: invalid signature", endpoint);
        return StatusCode::UNAUTHORIZED;
    }

    let mut decoder = GzDecoder::new(&body[..]);
    let mut json_bytes = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut json_bytes) {
        eprintln!("[{}] Failed to decompress: {}", endpoint, e);
        return StatusCode::BAD_REQUEST;
    }

    let json: serde_json::Value = match serde_json::from_slice(&json_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[{}] Invalid JSON: {}", endpoint, e);
            return StatusCode::BAD_REQUEST;
        }
    };

    let dir = std::path::Path::new(&state.output_dir);
    if let Err(e) = fs::create_dir_all(dir).await {
        eprintln!("[{}] Failed to create output dir: {}", endpoint, e);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    let path = dir.join(format!("{}.json", endpoint));
    let pretty = serde_json::to_string_pretty(&json).unwrap_or_default();
    if let Err(e) = fs::write(&path, pretty.as_bytes()).await {
        eprintln!("[{}] Failed to write file: {}", endpoint, e);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    println!(
        "[{}] OK — {} bytes decompressed, saved to {}",
        endpoint,
        json_bytes.len(),
        path.display()
    );
    StatusCode::OK
}

#[tokio::main]
async fn main() {
    if dotenvy::dotenv().is_err() {
        let _ = dotenvy::from_path("../.env");
    }

    let hmac_key_hex = std::env::var("HORSEACT_HMAC_KEY")
        .expect("HORSEACT_HMAC_KEY must be set in environment or .env file");
    let hmac_key = hex::decode(&hmac_key_hex)
        .expect("HORSEACT_HMAC_KEY must be a valid hex string");

    let api_key = std::env::var("API_KEY").unwrap_or_else(|_| "changeme".to_string());
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let output_dir = std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "received".to_string());

    let endpoint_config: serde_json::Value = std::fs::read_to_string("endpoints.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| {
            eprintln!("Warning: endpoints.json not found or invalid, serving empty config.");
            serde_json::Value::Array(vec![])
        });

    let state = Arc::new(AppState { api_key, hmac_key, output_dir, endpoint_config });

    let app = Router::new()
        .route("/config", get(get_config))
        .route("/ingest/:endpoint", post(ingest))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    println!("horseACT ingest server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
