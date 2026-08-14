use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use super::cdp::client::CdpClient;
use super::cdp::types::{
    AttachToTargetParams, AttachToTargetResult, CdpEvent, CloseTargetParams, CreateTargetParams,
    CreateTargetResult, EvaluateParams,
};
use super::cookies::{self, Cookie};
use crate::validation::{is_valid_session_name, sanitize_session_component, session_name_error};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageState {
    pub cookies: Vec<Cookie>,
    pub origins: Vec<OriginStorage>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginStorage {
    pub origin: String,
    pub local_storage: Vec<StorageEntry>,
    #[serde(default)]
    pub session_storage: Vec<StorageEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageEntry {
    pub name: String,
    pub value: String,
}

fn collect_frame_origins(tree: &Value, origins: &mut HashSet<String>) {
    if let Some(frame) = tree.get("frame") {
        if let Some(url_str) = frame.get("url").and_then(|v| v.as_str()) {
            if let Ok(parsed) = url::Url::parse(url_str) {
                let origin = parsed.origin().ascii_serialization();
                if origin != "null" && !origin.is_empty() {
                    origins.insert(origin);
                }
            }
        }
    }
    if let Some(children) = tree.get("childFrames").and_then(|v| v.as_array()) {
        for child in children {
            collect_frame_origins(child, origins);
        }
    }
}

fn normalize_included_origin(input: &str) -> Result<String, String> {
    let parsed = url::Url::parse(input).map_err(|_| {
        format!(
            "Invalid include origin '{}': expected an absolute HTTP(S) URL",
            input
        )
    })?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(format!(
            "Invalid include origin '{}': only HTTP(S) origins are supported",
            input
        ));
    }
    let origin = parsed.origin().ascii_serialization();
    if origin == "null" {
        return Err(format!(
            "Invalid include origin '{}': URL has no origin",
            input
        ));
    }
    Ok(origin)
}

/// Parse the JS-evaluated origin storage data into an OriginStorage struct.
fn parse_origin_storage(data: &Value) -> Option<OriginStorage> {
    if !data.is_object() {
        return None;
    }
    let origin = data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if origin.is_empty() || origin == "null" {
        return None;
    }
    let local_storage: Vec<StorageEntry> = data
        .get("localStorage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let session_storage: Vec<StorageEntry> = data
        .get("sessionStorage")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Some(OriginStorage {
        origin,
        local_storage,
        session_storage,
    })
}

/// Evaluate the storage-collection JS snippet and parse the result.
async fn eval_origin_storage(
    client: &CdpClient,
    session_id: &str,
    origin_js: &str,
) -> Option<OriginStorage> {
    let result = client
        .send_command_typed::<_, super::cdp::types::EvaluateResult>(
            "Runtime.evaluate",
            &EvaluateParams {
                expression: origin_js.to_string(),
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await
        .ok()?;
    let data = result.result.value.unwrap_or(Value::Null);
    parse_origin_storage(&data)
}

/// Create a temporary CDP target, navigate it to each origin to collect localStorage,
/// then close it. Uses Fetch interception to serve blank HTML instead of making real
/// network requests.
async fn collect_storage_via_temp_target(
    client: &CdpClient,
    origins: &[String],
    origin_js: &str,
) -> Result<Vec<OriginStorage>, String> {
    // Prefer a background target so headed sessions do not visibly switch
    // away from the user's page while cross-origin storage is collected.
    // Older CDP implementations may reject the experimental `background`
    // field, so retry with the broadly supported request shape.
    let create_result: CreateTargetResult = match client
        .send_command_typed(
            "Target.createTarget",
            &json!({ "url": "about:blank", "background": true }),
            None,
        )
        .await
    {
        Ok(result) => result,
        Err(_) => {
            client
                .send_command_typed(
                    "Target.createTarget",
                    &CreateTargetParams {
                        url: "about:blank".to_string(),
                    },
                    None,
                )
                .await?
        }
    };

    let target_id = create_result.target_id;

    // Ensure the target is closed even if attach or later steps fail
    let result = collect_storage_in_target(client, &target_id, origins, origin_js).await;

    let _ = client
        .send_command_typed::<_, Value>(
            "Target.closeTarget",
            &CloseTargetParams { target_id },
            None,
        )
        .await;

    result
}

async fn collect_storage_in_target(
    client: &CdpClient,
    target_id: &str,
    origins: &[String],
    origin_js: &str,
) -> Result<Vec<OriginStorage>, String> {
    let attach_result: AttachToTargetResult = client
        .send_command_typed(
            "Target.attachToTarget",
            &AttachToTargetParams {
                target_id: target_id.to_string(),
                flatten: true,
            },
            None,
        )
        .await?;

    let temp_session = &attach_result.session_id;

    client
        .send_command_no_params("Page.enable", Some(temp_session))
        .await?;
    client
        .send_command_no_params("Runtime.enable", Some(temp_session))
        .await?;
    client
        .send_command_no_params("Network.enable", Some(temp_session))
        .await?;
    client
        .send_command(
            "Network.setRequestInterception",
            Some(json!({
                "patterns": [{
                    "urlPattern": "*",
                    "interceptionStage": "Request"
                }]
            })),
            Some(temp_session),
        )
        .await?;

    let blank_response_b64 = blank_html_response_b64();
    let mut event_rx = client.subscribe();
    let mut results = Vec::new();

    for target_origin in origins {
        if navigate_to_intercepted_origin(
            client,
            temp_session,
            &mut event_rx,
            target_origin,
            &blank_response_b64,
        )
        .await
        .is_err()
        {
            continue;
        }

        if let Some(storage) = eval_origin_storage(client, temp_session, origin_js).await {
            if !storage.local_storage.is_empty() || !storage.session_storage.is_empty() {
                results.push(storage);
            }
        }
    }

    Ok(results)
}

async fn navigate_to_intercepted_origin(
    client: &CdpClient,
    session_id: &str,
    event_rx: &mut tokio::sync::broadcast::Receiver<CdpEvent>,
    target_origin: &str,
    blank_response_b64: &str,
) -> Result<(), String> {
    let nav_url = format!("{}/", target_origin.trim_end_matches('/'));
    client
        .send_command_no_wait(
            "Page.navigate",
            Some(json!({ "url": nav_url })),
            Some(session_id),
        )
        .await?;

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(tokio::time::Duration::from_secs(2), event_rx.recv()).await {
            Ok(Ok(evt)) if evt.session_id.as_deref() == Some(session_id) => {
                if evt.method == "Network.requestIntercepted" {
                    if let Some(interception_id) =
                        evt.params.get("interceptionId").and_then(|v| v.as_str())
                    {
                        client
                            .send_command(
                                "Network.continueInterceptedRequest",
                                Some(json!({
                                    "interceptionId": interception_id,
                                    "rawResponse": blank_response_b64
                                })),
                                Some(session_id),
                            )
                            .await?;
                    }
                } else if evt.method == "Page.loadEventFired" {
                    return Ok(());
                }
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => continue,
            Err(_) => break,
        }
    }

    Err(format!(
        "Timed out preparing storage origin {}",
        target_origin
    ))
}

fn blank_html_response_b64() -> String {
    // Keep Chrome from requesting /favicon.ico after the intercepted document loads.
    let body = r#"<html><head><link rel="icon" href="data:,"></head></html>"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body,
    );
    base64::engine::general_purpose::STANDARD.encode(response)
}

async fn restore_local_storage_via_temp_target(
    client: &CdpClient,
    origins: &[OriginStorage],
) -> Result<(), String> {
    if !origins
        .iter()
        .any(|origin| !origin.local_storage.is_empty())
    {
        return Ok(());
    }

    let create_result: CreateTargetResult = client
        .send_command_typed(
            "Target.createTarget",
            &CreateTargetParams {
                url: "about:blank".to_string(),
            },
            None,
        )
        .await?;
    let target_id = create_result.target_id;
    let result = restore_storage_in_target(client, &target_id, origins).await;

    let _ = client
        .send_command_typed::<_, Value>(
            "Target.closeTarget",
            &CloseTargetParams { target_id },
            None,
        )
        .await;

    result
}

async fn restore_storage_in_target(
    client: &CdpClient,
    target_id: &str,
    origins: &[OriginStorage],
) -> Result<(), String> {
    let attach_result: AttachToTargetResult = client
        .send_command_typed(
            "Target.attachToTarget",
            &AttachToTargetParams {
                target_id: target_id.to_string(),
                flatten: true,
            },
            None,
        )
        .await?;
    let temp_session = &attach_result.session_id;

    client
        .send_command_no_params("Page.enable", Some(temp_session))
        .await?;
    client
        .send_command_no_params("Runtime.enable", Some(temp_session))
        .await?;
    client
        .send_command_no_params("Network.enable", Some(temp_session))
        .await?;
    client
        .send_command(
            "Network.setRequestInterception",
            Some(json!({
                "patterns": [{
                    "urlPattern": "*",
                    "interceptionStage": "Request"
                }]
            })),
            Some(temp_session),
        )
        .await?;

    let blank_response_b64 = blank_html_response_b64();
    let mut event_rx = client.subscribe();

    for origin in origins {
        if origin.local_storage.is_empty() {
            continue;
        }

        navigate_to_intercepted_origin(
            client,
            temp_session,
            &mut event_rx,
            &origin.origin,
            &blank_response_b64,
        )
        .await?;

        for entry in &origin.local_storage {
            set_storage_entry(client, temp_session, "localStorage", entry).await?;
        }
    }

    Ok(())
}

async fn restore_session_storage_in_active_target(
    client: &CdpClient,
    session_id: &str,
    origins: &[OriginStorage],
) -> Result<(), String> {
    if !origins
        .iter()
        .any(|origin| !origin.session_storage.is_empty())
    {
        return Ok(());
    }

    client
        .send_command_no_params("Page.enable", Some(session_id))
        .await?;
    client
        .send_command_no_params("Runtime.enable", Some(session_id))
        .await?;
    client
        .send_command_no_params("Network.enable", Some(session_id))
        .await?;
    client
        .send_command(
            "Network.setRequestInterception",
            Some(json!({
                "patterns": [{
                    "urlPattern": "*",
                    "interceptionStage": "Request"
                }]
            })),
            Some(session_id),
        )
        .await?;

    let blank_response_b64 = blank_html_response_b64();
    let mut event_rx = client.subscribe();
    let result: Result<(), String> = async {
        for origin in origins {
            if origin.session_storage.is_empty() {
                continue;
            }

            navigate_to_intercepted_origin(
                client,
                session_id,
                &mut event_rx,
                &origin.origin,
                &blank_response_b64,
            )
            .await?;

            for entry in &origin.session_storage {
                set_storage_entry(client, session_id, "sessionStorage", entry).await?;
            }
        }
        Ok(())
    }
    .await;

    let disable_result = client
        .send_command(
            "Network.setRequestInterception",
            Some(json!({ "patterns": [] })),
            Some(session_id),
        )
        .await;
    result?;
    disable_result?;
    Ok(())
}

async fn set_storage_entry(
    client: &CdpClient,
    session_id: &str,
    storage_name: &str,
    entry: &StorageEntry,
) -> Result<(), String> {
    let expression = format!(
        "{}.setItem({}, {})",
        storage_name,
        serde_json::to_string(&entry.name).unwrap_or_default(),
        serde_json::to_string(&entry.value).unwrap_or_default(),
    );
    client
        .send_command_typed::<_, super::cdp::types::EvaluateResult>(
            "Runtime.evaluate",
            &EvaluateParams {
                expression,
                return_by_value: Some(true),
                await_promise: Some(false),
            },
            Some(session_id),
        )
        .await?;
    Ok(())
}

pub async fn save_state(
    client: &CdpClient,
    session_id: &str,
    path: Option<&str>,
    session_name: Option<&str>,
    session_id_str: &str,
    visited_origins: &HashSet<String>,
    included_origins: &[String],
) -> Result<String, String> {
    let cookies = cookies::get_all_cookies(client, session_id).await?;

    let origin_js = r#"(() => {
        const result = { origin: location.origin, localStorage: [], sessionStorage: [] };
        try {
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                result.localStorage.push({ name: key, value: localStorage.getItem(key) });
            }
        } catch(e) {}
        try {
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                result.sessionStorage.push({ name: key, value: sessionStorage.getItem(key) });
            }
        } catch(e) {}
        return result;
    })()"#;

    // Merge visited origins with current frame tree origins
    let mut all_origins = visited_origins.clone();
    for included_origin in included_origins {
        all_origins.insert(normalize_included_origin(included_origin)?);
    }
    if let Ok(tree_result) = client
        .send_command_no_params("Page.getFrameTree", Some(session_id))
        .await
    {
        if let Some(tree) = tree_result.get("frameTree") {
            collect_frame_origins(tree, &mut all_origins);
        }
    }

    // 1. Collect localStorage from the current page
    let mut origins = Vec::new();
    let mut current_origin = String::new();

    if let Some(storage) = eval_origin_storage(client, session_id, origin_js).await {
        current_origin = storage.origin.clone();
        if !storage.local_storage.is_empty() || !storage.session_storage.is_empty() {
            origins.push(storage);
        }
    }

    // 2. Collect localStorage from remaining origins via a disposable temp target
    all_origins.remove(&current_origin);
    if !all_origins.is_empty() {
        let remaining: Vec<String> = all_origins.into_iter().collect();
        if let Ok(temp_origins) =
            collect_storage_via_temp_target(client, &remaining, origin_js).await
        {
            origins.extend(temp_origins);
        }
    }

    let state = StorageState { cookies, origins };
    let json_str = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("Failed to serialize state: {}", e))?;

    let mut save_path = match path {
        Some(p) => p.to_string(),
        None => {
            let dir = get_sessions_dir();
            let _ = fs::create_dir_all(&dir);
            let name = session_name.unwrap_or("default");
            if !is_valid_session_name(name) {
                return Err(session_name_error(name));
            }
            dir.join(format!("{}-{}.json", name, session_id_str))
                .to_string_lossy()
                .to_string()
        }
    };

    if let Ok(key) = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY") {
        let encrypted = encrypt_data(json_str.as_bytes(), &key)?;
        save_path.push_str(".enc");
        fs::write(&save_path, &encrypted)
            .map_err(|e| format!("Failed to write state to {}: {}", save_path, e))?;
    } else {
        fs::write(&save_path, &json_str)
            .map_err(|e| format!("Failed to write state to {}: {}", save_path, e))?;
    }

    Ok(save_path)
}

pub async fn save_auto_state_transactional(
    client: &CdpClient,
    session_id: &str,
    session_name: &str,
    session_id_str: &str,
    visited_origins: &HashSet<String>,
) -> Result<String, String> {
    if !is_valid_session_name(session_name) {
        return Err(session_name_error(session_name));
    }

    let dir = get_sessions_dir();
    fs::create_dir_all(&dir)
        .map_err(|e| format!("Failed to create state directory {}: {}", dir.display(), e))?;

    let tmp_dir = dir.join(".tmp");
    fs::create_dir_all(&tmp_dir).map_err(|e| {
        format!(
            "Failed to create temporary state directory {}: {}",
            tmp_dir.display(),
            e
        )
    })?;

    let base_name = format!("{}-{}", session_name, session_id_str);
    let final_json_path = dir.join(format!("{}.json", base_name));
    let final_path = if std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").is_ok() {
        PathBuf::from(format!("{}.enc", final_json_path.to_string_lossy()))
    } else {
        final_json_path
    };
    let candidate_json_path = tmp_dir.join(format!(
        "{}-candidate-{}.json",
        base_name,
        std::process::id()
    ));
    let candidate_arg = candidate_json_path.to_string_lossy().to_string();

    let candidate_path = save_state(
        client,
        session_id,
        Some(&candidate_arg),
        Some(session_name),
        session_id_str,
        visited_origins,
        &[],
    )
    .await?;

    if let Err(err) = validate_state_file(&candidate_path) {
        let _ = fs::remove_file(&candidate_path);
        return Err(err);
    }

    let previous_path = PathBuf::from(format!("{}.previous", final_path.to_string_lossy()));
    if final_path.exists() {
        let _ = fs::remove_file(&previous_path);
        fs::rename(&final_path, &previous_path).map_err(|e| {
            format!(
                "Failed to rotate previous state {} to {}: {}",
                final_path.display(),
                previous_path.display(),
                e
            )
        })?;
    }

    let candidate = PathBuf::from(&candidate_path);
    if let Err(err) = fs::rename(&candidate, &final_path) {
        if previous_path.exists() && !final_path.exists() {
            let _ = fs::rename(&previous_path, &final_path);
        }
        return Err(format!(
            "Failed to promote state {} to {}: {}",
            candidate.display(),
            final_path.display(),
            err
        ));
    }
    if previous_path.exists() {
        let _ = fs::remove_file(&previous_path);
    }

    Ok(final_path.to_string_lossy().to_string())
}

fn read_state_json(path: &str) -> Result<String, String> {
    if is_encrypted_state(std::path::Path::new(path)) {
        let key = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").map_err(|_| {
            "Encrypted state file requires AGENT_BROWSER_ENCRYPTION_KEY".to_string()
        })?;
        let data =
            fs::read(path).map_err(|e| format!("Failed to read state from {}: {}", path, e))?;
        let decrypted = decrypt_data(&data, &key)?;
        Ok(String::from_utf8(decrypted)
            .map_err(|e| format!("Decrypted state is not valid UTF-8: {}", e))?)
    } else {
        match fs::read_to_string(path) {
            Ok(s) => Ok(s),
            Err(e) => {
                if let Ok(key) = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY") {
                    let enc_path = format!("{}.enc", path);
                    if let Ok(data) = fs::read(&enc_path) {
                        let decrypted = decrypt_data(&data, &key)?;
                        Ok(String::from_utf8(decrypted)
                            .map_err(|de| format!("Decrypted state is not valid UTF-8: {}", de))?)
                    } else {
                        Err(format!("Failed to read state from {}: {}", path, e))
                    }
                } else {
                    Err(format!("Failed to read state from {}: {}", path, e))
                }
            }
        }
    }
}

pub fn validate_state_file(path: &str) -> Result<(), String> {
    let json_str = read_state_json(path)?;
    let _: StorageState =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid state file: {}", e))?;
    Ok(())
}

pub async fn load_state(client: &CdpClient, session_id: &str, path: &str) -> Result<(), String> {
    let json_str = read_state_json(path)?;

    let state: StorageState =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid state file: {}", e))?;

    // Load cookies
    if !state.cookies.is_empty() {
        let cookie_values: Vec<Value> = state
            .cookies
            .iter()
            .map(Cookie::to_set_cookie_value)
            .collect();
        cookies::set_cookies(client, session_id, cookie_values, None).await?;
    }

    // Restore origin storage without contacting the saved origins. Real
    // navigation can trigger sign-in flows before the final requested URL opens
    // and invalidate freshly loaded cookies. localStorage is shared across tabs,
    // so it can use a disposable target. sessionStorage belongs to the active tab,
    // so it uses intercepted blank responses in that tab.
    restore_local_storage_via_temp_target(client, &state.origins).await?;
    restore_session_storage_in_active_target(client, session_id, &state.origins).await?;

    Ok(())
}

fn is_state_file(path: &std::path::Path) -> bool {
    let fname = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    fname.ends_with(".json")
        || fname.ends_with(".json.enc")
        || fname.ends_with(".json.previous")
        || fname.ends_with(".json.enc.previous")
}

fn is_encrypted_state(path: &std::path::Path) -> bool {
    let path = path.to_string_lossy();
    path.ends_with(".json.enc") || path.ends_with(".json.enc.previous")
}

pub fn state_list() -> Result<Value, String> {
    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "files": [], "directory": dir.to_string_lossy() }));
    }

    let mut files = Vec::new();

    let entries = fs::read_dir(&dir).map_err(|e| format!("Failed to read sessions dir: {}", e))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if is_state_file(&path) {
            let metadata = fs::metadata(&path).ok();
            let filename = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = metadata
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let encrypted = is_encrypted_state(&path);

            files.push(json!({
                "filename": filename,
                "path": path.to_string_lossy(),
                "size": size,
                "modified": modified,
                "encrypted": encrypted,
            }));
        }
    }

    Ok(json!({ "files": files, "directory": dir.to_string_lossy() }))
}

pub fn state_show(path: &str) -> Result<Value, String> {
    let encrypted = is_encrypted_state(std::path::Path::new(path));
    let json_str = if encrypted {
        let key = std::env::var("AGENT_BROWSER_ENCRYPTION_KEY").map_err(|_| {
            "Encrypted state file requires AGENT_BROWSER_ENCRYPTION_KEY".to_string()
        })?;
        let data = fs::read(path).map_err(|e| format!("Failed to read state file: {}", e))?;
        let decrypted = decrypt_data(&data, &key)?;
        String::from_utf8(decrypted)
            .map_err(|e| format!("Decrypted state is not valid UTF-8: {}", e))?
    } else {
        fs::read_to_string(path).map_err(|e| format!("Failed to read state file: {}", e))?
    };

    let state: StorageState =
        serde_json::from_str(&json_str).map_err(|e| format!("Invalid state file: {}", e))?;

    let metadata = fs::metadata(path).ok();
    let filename = std::path::Path::new(path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    Ok(json!({
        "filename": filename,
        "path": path,
        "size": metadata.as_ref().map(|m| m.len()).unwrap_or(0),
        "modified": metadata.as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "encrypted": encrypted,
        "summary": format!("{} cookies, {} origins", state.cookies.len(), state.origins.len()),
        "state": state,
    }))
}

pub fn state_clear(path: Option<&str>) -> Result<Value, String> {
    if let Some(p) = path {
        fs::remove_file(p).map_err(|e| format!("Failed to delete state: {}", e))?;
        return Ok(json!({ "deleted": p }));
    }

    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "deleted": 0 }));
    }

    let mut count = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if is_state_file(&path) {
                let _ = fs::remove_file(&path);
                count += 1;
            }
        }
    }

    Ok(json!({ "deleted": count }))
}

pub fn state_clean(max_age_days: u64) -> Result<Value, String> {
    let dir = get_sessions_dir();
    if !dir.exists() {
        return Ok(json!({ "cleaned": 0, "keptCount": 0, "days": max_age_days }));
    }

    let now = std::time::SystemTime::now();
    let max_age = std::time::Duration::from_secs(max_age_days * 86400);
    let mut deleted = 0;
    let mut kept = 0;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !is_state_file(&path) {
                continue;
            }

            if let Ok(metadata) = fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = now.duration_since(modified) {
                        if age > max_age {
                            let _ = fs::remove_file(&path);
                            deleted += 1;
                            continue;
                        }
                    }
                }
            }
            kept += 1;
        }
    }

    Ok(json!({ "cleaned": deleted, "keptCount": kept, "days": max_age_days }))
}

pub fn state_rename(old_path: &str, new_name: &str) -> Result<Value, String> {
    let old = PathBuf::from(old_path);
    if !old.exists() {
        return Err(format!("State file not found: {}", old_path));
    }

    let fallback = PathBuf::from(".");
    let dir = old.parent().unwrap_or(&fallback);
    let new_path = dir.join(format!("{}.json", new_name));

    fs::rename(&old, &new_path).map_err(|e| format!("Failed to rename state: {}", e))?;

    Ok(json!({
        "renamed": true,
        "from": old_path,
        "to": new_path.to_string_lossy(),
    }))
}

fn encrypt_data(data: &[u8], key_str: &str) -> Result<Vec<u8>, String> {
    let mut hasher = Sha256::new();
    hasher.update(key_str.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("Invalid key: {}", e))?;

    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| format!("Failed to generate nonce: {}", e))?;
    let ciphertext = cipher
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_data(data: &[u8], key_str: &str) -> Result<Vec<u8>, String> {
    if data.len() < 13 {
        return Err("Ciphertext too short".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);

    let mut hasher = Sha256::new();
    hasher.update(key_str.as_bytes());
    let key_bytes = hasher.finalize();
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| format!("Invalid key: {}", e))?;
    let plaintext = cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(plaintext)
}

pub fn find_auto_state_file(session_name: &str) -> Option<String> {
    if !is_valid_session_name(session_name) {
        return None;
    }

    let dir = get_sessions_dir();
    if !dir.exists() {
        return None;
    }
    let prefix = format!("{}-", session_name);
    let mut best_path: Option<(String, std::time::SystemTime)> = None;

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let fname = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let is_match = fname.starts_with(&prefix)
                && (fname.ends_with(".json") || fname.ends_with(".json.enc"));
            if !is_match {
                continue;
            }
            let modified = fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best_path.as_ref().is_none_or(|(_, t)| modified > *t) {
                best_path = Some((path.to_string_lossy().to_string(), modified));
            }
        }
    }
    best_path.map(|(p, _)| p)
}

/// Dispatch a state management command from its JSON payload.
/// Returns `Some(result)` for recognised state_* actions, `None` otherwise.
pub fn dispatch_state_command(cmd: &Value) -> Option<Result<Value, String>> {
    let action = cmd.get("action").and_then(|v| v.as_str())?;
    match action {
        "state_list" => Some(state_list()),
        "state_show" => Some(
            cmd.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' parameter".to_string())
                .and_then(state_show),
        ),
        "state_clear" => {
            let path = cmd.get("path").and_then(|v| v.as_str());
            Some(state_clear(path))
        }
        "state_clean" => {
            let days = cmd.get("days").and_then(|v| v.as_u64()).unwrap_or(30);
            Some(state_clean(days))
        }
        "state_rename" => Some(
            cmd.get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Missing 'path' parameter".to_string())
                .and_then(|path| {
                    cmd.get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| "Missing 'name' parameter".to_string())
                        .and_then(|name| state_rename(path, name))
                }),
        ),
        _ => None,
    }
}

/// Return the agent-browser state root. `AGENT_BROWSER_HOME` can relocate it;
/// otherwise an unwritable OS home falls back to a short per-user temp path.
/// This is the parent of `sessions/`, auth storage, and the encryption key.
pub fn get_state_dir() -> PathBuf {
    let base = crate::paths::agent_browser_home();

    if let Ok(namespace) = std::env::var("AGENT_BROWSER_NAMESPACE") {
        let namespace = sanitize_session_component(&namespace);
        if !namespace.is_empty() {
            return base.join("namespaces").join(namespace).join("state");
        }
    }

    base
}

pub fn get_sessions_dir() -> PathBuf {
    get_state_dir().join("sessions")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_state_serialization() {
        let state = StorageState {
            cookies: vec![Cookie {
                name: "session".to_string(),
                value: "abc123".to_string(),
                domain: ".example.com".to_string(),
                path: "/".to_string(),
                expires: 0.0,
                size: 0,
                http_only: true,
                secure: false,
                session: true,
                same_site: Some("Lax".to_string()),
                priority: None,
                source_scheme: None,
                source_port: None,
                partition_key: None,
                partition_key_opaque: None,
            }],
            origins: vec![OriginStorage {
                origin: "https://example.com".to_string(),
                local_storage: vec![StorageEntry {
                    name: "key".to_string(),
                    value: "val".to_string(),
                }],
                session_storage: vec![],
            }],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: StorageState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cookies.len(), 1);
        assert_eq!(parsed.cookies[0].name, "session");
        assert_eq!(parsed.origins.len(), 1);
        assert_eq!(parsed.origins[0].local_storage.len(), 1);
    }

    #[test]
    fn test_storage_state_empty() {
        let state = StorageState {
            cookies: vec![],
            origins: vec![],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: StorageState = serde_json::from_str(&json).unwrap();
        assert!(parsed.cookies.is_empty());
        assert!(parsed.origins.is_empty());
    }

    #[test]
    fn test_state_show_nonexistent_file() {
        let result = state_show("/tmp/nonexistent-agent-browser-state-file.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_state_clear_nonexistent_file() {
        let result = state_clear(Some("/tmp/nonexistent-agent-browser-state-file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_state_file_matcher_includes_transactional_backups() {
        assert!(is_state_file(std::path::Path::new("auth.json")));
        assert!(is_state_file(std::path::Path::new("auth.json.enc")));
        assert!(is_state_file(std::path::Path::new("auth.json.previous")));
        assert!(is_state_file(std::path::Path::new(
            "auth.json.enc.previous"
        )));
        assert!(is_encrypted_state(std::path::Path::new(
            "auth.json.enc.previous"
        )));
    }

    #[test]
    fn test_state_clear_removes_transactional_backups() {
        let guard = crate::test_utils::EnvGuard::new(&["HOME", "AGENT_BROWSER_NAMESPACE"]);
        let dir = tempfile::tempdir().unwrap();
        guard.set("HOME", dir.path().to_str().unwrap());
        guard.remove("AGENT_BROWSER_NAMESPACE");

        let sessions = get_sessions_dir();
        fs::create_dir_all(&sessions).unwrap();
        fs::write(sessions.join("auth-test.json"), "{}").unwrap();
        fs::write(sessions.join("auth-test.json.previous"), "{}").unwrap();
        fs::write(sessions.join("auth-test.json.enc.previous"), "encrypted").unwrap();

        let result = state_clear(None).unwrap();

        assert_eq!(result["deleted"], 3);
        assert!(!sessions.join("auth-test.json").exists());
        assert!(!sessions.join("auth-test.json.previous").exists());
        assert!(!sessions.join("auth-test.json.enc.previous").exists());
    }

    #[test]
    fn test_state_rename_nonexistent() {
        let result = state_rename("/tmp/nonexistent-agent-browser-state-file.json", "new-name");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_state_list_returns_json() {
        let result = state_list().unwrap();
        assert!(result.get("files").is_some());
        assert!(result.get("directory").is_some());
    }

    #[test]
    fn test_sessions_dir_path() {
        let dir = get_sessions_dir();
        assert!(dir.to_string_lossy().contains("sessions"));
    }

    #[test]
    fn test_get_state_dir_namespace_scopes_sessions() {
        let _guard =
            crate::test_utils::EnvGuard::new(&["AGENT_BROWSER_NAMESPACE", "AGENT_BROWSER_HOME"]);
        _guard.set("AGENT_BROWSER_HOME", "/tmp/agent-browser-state-test");
        _guard.set("AGENT_BROWSER_NAMESPACE", "Worktree: One");

        let dir = get_state_dir();
        let expected_state_suffix = PathBuf::from("/tmp/agent-browser-state-test")
            .join("namespaces")
            .join("worktree-one")
            .join("state");
        let expected_sessions_suffix = expected_state_suffix.join("sessions");

        assert!(dir.ends_with(expected_state_suffix));
        assert!(get_sessions_dir().ends_with(expected_sessions_suffix));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plain = b"hello world";
        let key = "test-secret-key";
        let encrypted = encrypt_data(plain, key).unwrap();
        assert!(encrypted.len() > 12);
        assert_ne!(&encrypted[12..], plain);
        let decrypted = decrypt_data(&encrypted, key).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let plain = b"secret data";
        let encrypted = encrypt_data(plain, "key1").unwrap();
        let result = decrypt_data(&encrypted, "key2");
        assert!(result.is_err());
    }

    #[test]
    fn test_cookie_serde_roundtrip() {
        let cookie = Cookie {
            name: "test".to_string(),
            value: "123".to_string(),
            domain: ".test.com".to_string(),
            path: "/api".to_string(),
            expires: 1700000000.0,
            size: 7,
            http_only: false,
            secure: true,
            session: false,
            same_site: Some("Strict".to_string()),
            priority: Some("High".to_string()),
            source_scheme: Some("Secure".to_string()),
            source_port: Some(443),
            partition_key: Some(cookies::CookiePartitionKey {
                top_level_site: "https://top.example".to_string(),
                has_cross_site_ancestor: true,
            }),
            partition_key_opaque: Some(false),
        };

        let json = serde_json::to_value(&cookie).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["httpOnly"], false);
        assert_eq!(json["secure"], true);
        assert_eq!(json["sameSite"], "Strict");
        assert_eq!(json["priority"], "High");
        assert_eq!(json["sourceScheme"], "Secure");
        assert_eq!(json["sourcePort"], 443);
        assert_eq!(
            json["partitionKey"],
            json!({
                "topLevelSite": "https://top.example",
                "hasCrossSiteAncestor": true
            })
        );

        let set_cookie = cookie.to_set_cookie_value();
        assert_eq!(set_cookie["partitionKey"], json["partitionKey"]);
        assert!(set_cookie.get("size").is_none());
        assert!(set_cookie.get("session").is_none());
        assert!(set_cookie.get("partitionKeyOpaque").is_none());
    }

    #[test]
    fn test_normalize_included_origin_uses_only_scheme_host_and_port() {
        assert_eq!(
            normalize_included_origin("https://sso.example.com/login?next=%2F").unwrap(),
            "https://sso.example.com"
        );
        assert_eq!(
            normalize_included_origin("http://localhost:4173/path").unwrap(),
            "http://localhost:4173"
        );
        assert!(normalize_included_origin("file:///tmp/auth.html").is_err());
        assert!(normalize_included_origin("sso.example.com").is_err());
    }

    #[test]
    fn test_dispatch_state_command_routes_state_list() {
        let cmd = serde_json::json!({ "action": "state_list" });
        let result = dispatch_state_command(&cmd);
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_dispatch_state_command_returns_none_for_unknown() {
        let cmd = serde_json::json!({ "action": "navigate" });
        assert!(dispatch_state_command(&cmd).is_none());
    }

    #[test]
    fn test_dispatch_state_command_returns_none_for_missing_action() {
        let cmd = serde_json::json!({});
        assert!(dispatch_state_command(&cmd).is_none());
    }

    #[test]
    fn test_dispatch_state_show_missing_path() {
        let cmd = serde_json::json!({ "action": "state_show" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'path' parameter");
    }

    #[test]
    fn test_dispatch_state_rename_missing_params() {
        let cmd = serde_json::json!({ "action": "state_rename" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'path' parameter");

        let cmd = serde_json::json!({ "action": "state_rename", "path": "/tmp/test.json" });
        let result = dispatch_state_command(&cmd).unwrap();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Missing 'name' parameter");
    }
}
