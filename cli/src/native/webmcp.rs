use serde_json::{json, Map, Value};
use std::time::Duration;
use tokio::sync::broadcast;

use super::browser::{format_tab_id, BrowserManager};
use super::cdp::types::CdpEvent;

pub const API_VERSION: u64 = 1;

const LIST_EVENT_TIMEOUT: Duration = Duration::from_secs(1);
const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

const UNSUPPORTED_PREFIX: &str = "webmcp_unsupported:";
const TOOL_NOT_FOUND_PREFIX: &str = "webmcp_tool_not_found:";
const TOOL_AMBIGUOUS_PREFIX: &str = "webmcp_tool_ambiguous:";
const CALL_TIMEOUT_PREFIX: &str = "webmcp_call_timeout:";

pub fn unsupported(message: impl AsRef<str>) -> String {
    format!("{} {}", UNSUPPORTED_PREFIX, message.as_ref())
}

pub fn error_code(message: &str) -> &'static str {
    if message.starts_with(UNSUPPORTED_PREFIX) {
        "webmcp_unsupported"
    } else if message.starts_with(TOOL_NOT_FOUND_PREFIX) {
        "webmcp_tool_not_found"
    } else if message.starts_with(TOOL_AMBIGUOUS_PREFIX) {
        "webmcp_tool_ambiguous"
    } else if message.starts_with(CALL_TIMEOUT_PREFIX) {
        "webmcp_call_timeout"
    } else {
        "webmcp_command_failed"
    }
}

pub fn with_api_version(value: Value) -> Value {
    match value {
        Value::Object(mut object) => {
            object.insert("apiVersion".to_string(), json!(API_VERSION));
            Value::Object(object)
        }
        other => json!({
            "apiVersion": API_VERSION,
            "value": other,
        }),
    }
}

fn session_matches(event: &CdpEvent, session_id: &str) -> bool {
    match (&event.session_id, session_id.is_empty()) {
        (Some(event_session), _) => event_session == session_id,
        (None, true) => true,
        (None, false) => false,
    }
}

fn normalize_tool(tool: &Value) -> Option<Value> {
    let object = tool.as_object()?;
    let name = object.get("name")?.as_str()?;
    let description = object
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let frame_id = object.get("frameId")?.as_str()?;
    let input_schema = object
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({ "type": "object" }));
    let backend_node_id = object.get("backendNodeId").cloned();

    let mut normalized = Map::new();
    normalized.insert("name".to_string(), json!(name));
    normalized.insert("description".to_string(), json!(description));
    normalized.insert("inputSchema".to_string(), input_schema);
    normalized.insert("frameId".to_string(), json!(frame_id));
    normalized.insert(
        "source".to_string(),
        json!(if backend_node_id.is_some() {
            "declarative"
        } else {
            "imperative"
        }),
    );
    if let Some(annotations) = object.get("annotations") {
        normalized.insert("annotations".to_string(), annotations.clone());
    }
    if let Some(backend_node_id) = backend_node_id {
        normalized.insert("backendNodeId".to_string(), backend_node_id);
    }
    Some(Value::Object(normalized))
}

fn sort_tools(tools: &mut [Value]) {
    tools.sort_by(|left, right| {
        let left_key = (
            left.get("frameId").and_then(Value::as_str).unwrap_or(""),
            left.get("name").and_then(Value::as_str).unwrap_or(""),
        );
        let right_key = (
            right.get("frameId").and_then(Value::as_str).unwrap_or(""),
            right.get("name").and_then(Value::as_str).unwrap_or(""),
        );
        left_key.cmp(&right_key)
    });
}

fn unsupported_enable_error(error: String) -> String {
    unsupported(format!(
        "Chrome does not expose the WebMCP CDP domain. Launch Chrome with WebMCP enabled and retry: {}",
        error
    ))
}

fn active_context(manager: &BrowserManager) -> Result<(String, String, String, String), String> {
    let session_id = manager.active_session_id()?.to_string();
    let target_id = manager.active_target_id()?.to_string();
    let active_tab_id = manager.active_tab_id();
    let page = manager
        .pages_list()
        .into_iter()
        .find(|page| Some(page.tab_id) == active_tab_id)
        .ok_or_else(|| "No active page".to_string())?;
    Ok((session_id, target_id, format_tab_id(page.tab_id), page.url))
}

async fn receive_tools_added(
    events: &mut broadcast::Receiver<CdpEvent>,
    session_id: &str,
) -> Result<Vec<Value>, String> {
    let receive = async {
        loop {
            match events.recv().await {
                Ok(event)
                    if event.method == "WebMCP.toolsAdded"
                        && session_matches(&event, session_id) =>
                {
                    let mut tools = event
                        .params
                        .get("tools")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(normalize_tool)
                        .collect::<Vec<_>>();
                    sort_tools(&mut tools);
                    return Ok(tools);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err("WebMCP CDP event channel closed".to_string())
                }
            }
        }
    };

    match tokio::time::timeout(LIST_EVENT_TIMEOUT, receive).await {
        Ok(result) => result,
        Err(_) => Ok(Vec::new()),
    }
}

pub async fn list(manager: &BrowserManager) -> Result<Value, String> {
    let (session_id, target_id, tab_id, page_url) = active_context(manager)?;
    let mut events = manager.client.subscribe();
    manager
        .client
        .send_command_no_params(
            "WebMCP.enable",
            if session_id.is_empty() {
                None
            } else {
                Some(&session_id)
            },
        )
        .await
        .map_err(unsupported_enable_error)?;
    let tools = receive_tools_added(&mut events, &session_id).await?;

    Ok(json!({
        "tools": tools,
        "count": tools.len(),
        "page": {
            "tabId": tab_id,
            "targetId": target_id,
            "url": page_url,
        },
    }))
}

fn resolve_tool(tools: &[Value], tool_name: &str, frame_id: Option<&str>) -> Result<Value, String> {
    let matches = tools
        .iter()
        .filter(|tool| {
            tool.get("name").and_then(Value::as_str) == Some(tool_name)
                && frame_id.is_none_or(|frame_id| {
                    tool.get("frameId").and_then(Value::as_str) == Some(frame_id)
                })
        })
        .cloned()
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [tool] => Ok(tool.clone()),
        [] => Err(format!(
            "{} No WebMCP tool named '{}'{} is registered on the active page",
            TOOL_NOT_FOUND_PREFIX,
            tool_name,
            frame_id
                .map(|frame_id| format!(" in frame {}", frame_id))
                .unwrap_or_default()
        )),
        _ => {
            let frames = matches
                .iter()
                .filter_map(|tool| tool.get("frameId").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "{} WebMCP tool '{}' is registered in multiple frames ({}). Retry with --frame-id <id>",
                TOOL_AMBIGUOUS_PREFIX, tool_name, frames
            ))
        }
    }
}

async fn receive_tool_response(
    manager: &BrowserManager,
    events: &mut broadcast::Receiver<CdpEvent>,
    session_id: &str,
    invocation_id: &str,
    timeout: Duration,
) -> Result<Value, String> {
    let receive = async {
        loop {
            match events.recv().await {
                Ok(event)
                    if event.method == "WebMCP.toolResponded"
                        && session_matches(&event, session_id)
                        && event.params.get("invocationId").and_then(Value::as_str)
                            == Some(invocation_id) =>
                {
                    return Ok(event.params);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err("WebMCP CDP event channel closed".to_string())
                }
            }
        }
    };

    match tokio::time::timeout(timeout, receive).await {
        Ok(result) => result,
        Err(_) => {
            let _ = manager
                .client
                .send_command(
                    "WebMCP.cancelInvocation",
                    Some(json!({ "invocationId": invocation_id })),
                    if session_id.is_empty() {
                        None
                    } else {
                        Some(session_id)
                    },
                )
                .await;
            Err(format!(
                "{} WebMCP invocation {} did not respond within {}ms and was canceled",
                CALL_TIMEOUT_PREFIX,
                invocation_id,
                timeout.as_millis()
            ))
        }
    }
}

pub async fn call(
    manager: &BrowserManager,
    tool_name: &str,
    input: Value,
    frame_id: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<Value, String> {
    let list_result = list(manager).await?;
    let tools = list_result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| "WebMCP tool list returned an invalid response".to_string())?;
    let tool = resolve_tool(tools, tool_name, frame_id)?;
    let resolved_frame_id = tool
        .get("frameId")
        .and_then(Value::as_str)
        .ok_or_else(|| "WebMCP tool is missing its frameId".to_string())?;
    let (session_id, target_id, tab_id, page_url) = active_context(manager)?;

    let mut events = manager.client.subscribe();
    let invoke_result = manager
        .client
        .send_command(
            "WebMCP.invokeTool",
            Some(json!({
                "frameId": resolved_frame_id,
                "toolName": tool_name,
                "input": input,
            })),
            if session_id.is_empty() {
                None
            } else {
                Some(&session_id)
            },
        )
        .await
        .map_err(|error| format!("WebMCP.invokeTool failed: {}", error))?;
    let invocation_id = invoke_result
        .get("invocationId")
        .and_then(Value::as_str)
        .ok_or_else(|| "WebMCP.invokeTool returned no invocationId".to_string())?;
    let response = receive_tool_response(
        manager,
        &mut events,
        &session_id,
        invocation_id,
        timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_CALL_TIMEOUT),
    )
    .await?;
    let status = response
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("Error")
        .to_ascii_lowercase();

    let mut result = Map::new();
    result.insert("invocationId".to_string(), json!(invocation_id));
    result.insert("status".to_string(), json!(status));
    result.insert("tool".to_string(), tool);
    result.insert("trust".to_string(), json!("untrusted"));
    result.insert(
        "page".to_string(),
        json!({
            "tabId": tab_id,
            "targetId": target_id,
            "url": page_url,
        }),
    );
    if let Some(output) = response.get("output") {
        result.insert("output".to_string(), output.clone());
    }
    if response.get("errorText").is_some() || response.get("exception").is_some() {
        let mut error = Map::new();
        error.insert(
            "message".to_string(),
            json!(response
                .get("errorText")
                .and_then(Value::as_str)
                .unwrap_or("WebMCP tool invocation failed")),
        );
        if let Some(exception) = response.get("exception") {
            error.insert("exception".to_string(), exception.clone());
        }
        result.insert("error".to_string(), Value::Object(error));
    }
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_sorts_tools() {
        let imperative = normalize_tool(&json!({
            "name": "zeta",
            "description": "Z",
            "inputSchema": { "type": "object" },
            "frameId": "frame-b",
            "stackTrace": { "callFrames": [] }
        }))
        .unwrap();
        let declarative = normalize_tool(&json!({
            "name": "alpha",
            "description": "A",
            "inputSchema": { "type": "object" },
            "frameId": "frame-a",
            "backendNodeId": 42
        }))
        .unwrap();
        let mut tools = vec![imperative, declarative];
        sort_tools(&mut tools);
        assert_eq!(tools[0]["name"], "alpha");
        assert_eq!(tools[0]["source"], "declarative");
        assert_eq!(tools[1]["source"], "imperative");
        assert!(tools[1].get("stackTrace").is_none());
    }

    #[test]
    fn resolves_duplicate_names_by_frame() {
        let tools = vec![
            json!({ "name": "search", "frameId": "a" }),
            json!({ "name": "search", "frameId": "b" }),
        ];
        let error = resolve_tool(&tools, "search", None).unwrap_err();
        assert_eq!(error_code(&error), "webmcp_tool_ambiguous");
        assert_eq!(
            resolve_tool(&tools, "search", Some("b")).unwrap()["frameId"],
            "b"
        );
    }

    #[test]
    fn exposes_stable_error_codes() {
        assert_eq!(
            error_code(&unsupported("Safari backend")),
            "webmcp_unsupported"
        );
        assert_eq!(
            error_code("webmcp_unsupported: no method"),
            "webmcp_unsupported"
        );
        assert_eq!(
            error_code("webmcp_tool_not_found: missing"),
            "webmcp_tool_not_found"
        );
        assert_eq!(
            error_code("webmcp_call_timeout: late"),
            "webmcp_call_timeout"
        );
    }
}
