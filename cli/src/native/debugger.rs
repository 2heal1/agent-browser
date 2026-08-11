//! Lock-independent Chrome Debugger control plane.
//!
//! Ordinary daemon commands hold the global `DaemonState` mutex while they
//! await renderer-bound CDP commands. A JavaScript breakpoint can pause that
//! renderer indefinitely, so pause inspection and recovery must not acquire
//! the same mutex. `DebuggerController` owns only short-lived synchronous
//! state locks and sends CDP commands through the shared client directly.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex as AsyncMutex, Notify};

use super::browser::{format_tab_id, PageInfo};
use super::cdp::client::CdpClient;
use super::cdp::types::CdpEvent;
use super::policy::{ActionPolicy, ConfirmActions, PolicyResult};

const MAX_DEBUG_EVENTS: usize = 10_000;
const MAX_DEBUG_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_LOGPOINT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_LOGPOINT_EXPRESSIONS: usize = 16;
const MAX_BREAKPOINT_VERIFICATION_CANDIDATES: usize = 128;
const MAX_DEBUG_SOURCE_BYTES: usize = 32 * 1024 * 1024;
const SOURCE_MATCH_CONTEXT_UTF16: usize = 160;
const LOGPOINT_BINDING_PREFIX: &str = "__agent_browser_debug_hit_";
static NEXT_PROBE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct DebugSession {
    tab_id: String,
    target_id: String,
    session_id: String,
    document_generation: u64,
    loader_id: Option<String>,
}

#[derive(Debug, Clone)]
struct PauseRecord {
    pause_id: String,
    connection_generation: u64,
    tab_id: String,
    session_id: String,
    document_generation: u64,
    reason: String,
    hit_breakpoints: Vec<String>,
    probe_ids: Vec<String>,
    call_frames: Vec<Value>,
    data: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Breakpoint,
    Logpoint,
}

type RebindCandidate = (
    String,
    ProbeKind,
    Value,
    Option<String>,
    Option<String>,
    Vec<String>,
    Value,
);

struct BreakpointResolutionRequest<'a> {
    line: u64,
    column: u64,
    column_explicit: bool,
    mode: &'a str,
    max_lines: u64,
    max_utf16_distance: u64,
}

impl ProbeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Breakpoint => "breakpoint",
            Self::Logpoint => "logpoint",
        }
    }
}

#[derive(Debug, Clone)]
struct PhysicalProbe {
    physical_id: String,
    cdp_breakpoint_id: String,
    probe_id: String,
    connection_generation: u64,
    session_id: String,
    document_generation: u64,
    script_id: String,
    execution_context_id: Option<u64>,
    requested_location: Value,
    actual_location: Value,
}

impl PhysicalProbe {
    fn to_json(&self) -> Value {
        json!({
            "physicalId": self.physical_id,
            "cdpBreakpointId": self.cdp_breakpoint_id,
            "probeId": self.probe_id,
            "connectionGeneration": self.connection_generation,
            "sessionId": self.session_id,
            "documentGeneration": self.document_generation,
            "scriptId": self.script_id,
            "executionContextId": self.execution_context_id,
            "requestedLocation": self.requested_location,
            "actualLocation": self.actual_location,
        })
    }
}

#[derive(Debug, Clone)]
struct LogicalProbe {
    probe_id: String,
    kind: ProbeKind,
    enabled: bool,
    persistent: bool,
    status: String,
    condition: Option<String>,
    when: Option<String>,
    expressions: Vec<String>,
    tags: serde_json::Map<String, Value>,
    target: Value,
    physical_ids: Vec<String>,
}

impl LogicalProbe {
    fn to_json(&self, physical: &HashMap<String, PhysicalProbe>) -> Value {
        let bindings: Vec<Value> = self
            .physical_ids
            .iter()
            .filter_map(|id| physical.get(id))
            .map(PhysicalProbe::to_json)
            .collect();
        json!({
            "probeId": self.probe_id,
            "kind": self.kind.as_str(),
            "enabled": self.enabled,
            "persistent": self.persistent,
            "status": self.status,
            "condition": self.condition,
            "when": self.when,
            "expressions": self.expressions,
            "tags": self.tags,
            "target": self.target,
            "bindings": bindings,
        })
    }
}

impl PauseRecord {
    fn to_json(&self) -> Value {
        json!({
            "pauseId": self.pause_id,
            "connectionGeneration": self.connection_generation,
            "tabId": self.tab_id,
            "sessionId": self.session_id,
            "documentGeneration": self.document_generation,
            "reason": self.reason,
            "hitBreakpoints": self.hit_breakpoints,
            "probeIds": self.probe_ids,
            "callFrames": self.call_frames,
            "data": self.data,
        })
    }
}

struct ControllerState {
    engine: String,
    connection_generation: u64,
    client: Option<Arc<CdpClient>>,
    sessions: HashMap<String, DebugSession>,
    active_session: Option<String>,
    enabled_sessions: HashSet<String>,
    execution_contexts: HashMap<String, HashSet<u64>>,
    binding_sessions: HashSet<String>,
    paused_sessions: HashMap<String, PauseRecord>,
    scripts: HashMap<(String, String), Value>,
    logical_probes: HashMap<String, LogicalProbe>,
    physical_probes: HashMap<String, PhysicalProbe>,
    physical_by_cdp_breakpoint: HashMap<String, String>,
    binding_name: String,
    binding_nonce: String,
    event_bytes: usize,
    events: VecDeque<Value>,
    latest_sequence: u64,
    dropped_through_sequence: Option<u64>,
    last_transport_gap_sequence: Option<u64>,
}

impl Default for ControllerState {
    fn default() -> Self {
        Self {
            engine: "chrome".to_string(),
            connection_generation: 0,
            client: None,
            sessions: HashMap::new(),
            active_session: None,
            enabled_sessions: HashSet::new(),
            execution_contexts: HashMap::new(),
            binding_sessions: HashSet::new(),
            paused_sessions: HashMap::new(),
            scripts: HashMap::new(),
            logical_probes: HashMap::new(),
            physical_probes: HashMap::new(),
            physical_by_cdp_breakpoint: HashMap::new(),
            binding_name: String::new(),
            binding_nonce: String::new(),
            event_bytes: 0,
            events: VecDeque::new(),
            latest_sequence: 0,
            dropped_through_sequence: None,
            last_transport_gap_sequence: None,
        }
    }
}

/// Debugger state and event processing that remains available while an
/// ordinary daemon command is blocked on a paused renderer.
pub struct DebuggerController {
    state: RwLock<ControllerState>,
    listener: Mutex<Option<tokio::task::JoinHandle<()>>>,
    probe_mutation: AsyncMutex<()>,
    pending_confirmation: Mutex<Option<PendingDebugConfirmation>>,
    event_notify: Notify,
}

#[derive(Clone)]
struct PendingDebugConfirmation {
    confirmation_id: String,
    category: String,
    command: Value,
}

impl Default for DebuggerController {
    fn default() -> Self {
        Self::new()
    }
}

impl DebuggerController {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(ControllerState::default()),
            listener: Mutex::new(None),
            probe_mutation: AsyncMutex::new(()),
            pending_confirmation: Mutex::new(None),
            event_notify: Notify::new(),
        }
    }

    /// Replace the current browser connection and start a dedicated CDP event
    /// listener. The listener never acquires the daemon's `DaemonState` mutex.
    pub fn attach_browser(
        self: &Arc<Self>,
        client: Arc<CdpClient>,
        pages: Vec<PageInfo>,
        active_tab_id: Option<u32>,
    ) {
        if let Some(task) = self.listener.lock().unwrap().take() {
            task.abort();
        }

        let generation = {
            let mut state = self.state.write().unwrap();
            let old_generation = state.connection_generation;
            if state.client.is_some() {
                push_event_locked(
                    &mut state,
                    "connection-reset",
                    None,
                    json!({ "previousConnectionGeneration": old_generation }),
                );
            }
            state.connection_generation = old_generation.saturating_add(1);
            state.client = Some(client.clone());
            state.sessions.clear();
            state.enabled_sessions.clear();
            state.execution_contexts.clear();
            state.binding_sessions.clear();
            state.paused_sessions.clear();
            state.scripts.clear();
            mark_all_probes_stale_locked(&mut state, "connection-reset");
            state.physical_probes.clear();
            state.physical_by_cdp_breakpoint.clear();
            let binding_suffix = uuid::Uuid::new_v4().simple().to_string();
            state.binding_name = format!("{}{}", LOGPOINT_BINDING_PREFIX, binding_suffix);
            state.binding_nonce = uuid::Uuid::new_v4().simple().to_string();
            let mut attached_sessions = Vec::new();
            for page in pages {
                let session = DebugSession {
                    tab_id: format_tab_id(page.tab_id),
                    target_id: page.target_id,
                    session_id: page.session_id.clone(),
                    document_generation: 1,
                    loader_id: None,
                };
                attached_sessions.push(session.clone());
                state.sessions.insert(page.session_id, session);
            }
            state.active_session = active_tab_id.and_then(|tab_id| {
                let tab_id = format_tab_id(tab_id);
                state
                    .sessions
                    .values()
                    .find(|session| session.tab_id == tab_id)
                    .map(|session| session.session_id.clone())
            });
            let connection_generation = state.connection_generation;
            push_event_locked(
                &mut state,
                "connection-attached",
                None,
                json!({ "connectionGeneration": connection_generation }),
            );
            for session in attached_sessions {
                push_event_locked(
                    &mut state,
                    "target-attached",
                    Some(&session.session_id),
                    json!({
                        "targetId": session.target_id,
                        "tabId": session.tab_id,
                    }),
                );
            }
            state.connection_generation
        };

        self.event_notify.notify_waiters();
        let mut rx = client.subscribe();
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let Some(controller) = weak.upgrade() else {
                            break;
                        };
                        let parsed_script = if event.method == "Debugger.scriptParsed" {
                            event.session_id.clone().zip(
                                event
                                    .params
                                    .get("scriptId")
                                    .and_then(Value::as_str)
                                    .map(ToString::to_string),
                            )
                        } else {
                            None
                        };
                        controller.handle_event(generation, event);
                        if let Some((session_id, script_id)) = parsed_script {
                            controller
                                .reconcile_persistent_probes(generation, &session_id, &script_id)
                                .await;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let Some(controller) = weak.upgrade() else {
                            break;
                        };
                        controller.record_transport_gap(generation, count);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        *self.listener.lock().unwrap() = Some(task);
    }

    pub fn detach_browser(&self, reason: &str) {
        if let Some(task) = self.listener.lock().unwrap().take() {
            task.abort();
        }
        let mut state = self.state.write().unwrap();
        if state.client.is_none() {
            return;
        }
        let generation = state.connection_generation;
        let paused: Vec<Value> = state
            .paused_sessions
            .values()
            .map(PauseRecord::to_json)
            .collect();
        push_event_locked(
            &mut state,
            "connection-reset",
            None,
            json!({
                "previousConnectionGeneration": generation,
                "reason": reason,
                "invalidatedPauses": paused,
            }),
        );
        state.client = None;
        state.sessions.clear();
        state.active_session = None;
        state.enabled_sessions.clear();
        state.execution_contexts.clear();
        state.binding_sessions.clear();
        state.paused_sessions.clear();
        state.scripts.clear();
        mark_all_probes_stale_locked(&mut state, reason);
        state.physical_probes.clear();
        state.physical_by_cdp_breakpoint.clear();
        self.event_notify.notify_waiters();
    }

    pub fn set_engine(&self, engine: &str) {
        self.state.write().unwrap().engine = engine.to_string();
    }

    /// Synchronize stable tab IDs assigned by BrowserManager. This is called
    /// after target lifecycle processing and successful tab switches.
    pub fn sync_pages(&self, pages: Vec<PageInfo>, active_tab_id: Option<u32>) {
        let mut state = self.state.write().unwrap();
        let old_sessions: HashSet<String> = state.sessions.keys().cloned().collect();
        let mut next = HashMap::new();
        for page in pages {
            let existing = state.sessions.get(&page.session_id);
            next.insert(
                page.session_id.clone(),
                DebugSession {
                    tab_id: format_tab_id(page.tab_id),
                    target_id: page.target_id,
                    session_id: page.session_id,
                    document_generation: existing
                        .map(|session| session.document_generation)
                        .unwrap_or(1),
                    loader_id: existing.and_then(|session| session.loader_id.clone()),
                },
            );
        }
        let next_sessions: HashSet<String> = next.keys().cloned().collect();
        let attached: Vec<String> = next_sessions.difference(&old_sessions).cloned().collect();
        for detached in old_sessions.difference(&next_sessions) {
            let pause = state.paused_sessions.remove(detached).map(|p| p.to_json());
            push_event_locked(
                &mut state,
                "target-detached",
                Some(detached),
                json!({ "invalidatedPause": pause }),
            );
            invalidate_session_probes_locked(&mut state, detached, u64::MAX, "session-detached");
            push_event_locked(&mut state, "session-detached", Some(detached), json!({}));
            state.enabled_sessions.remove(detached);
            state.execution_contexts.remove(detached);
            state.binding_sessions.remove(detached);
            state
                .scripts
                .retain(|(session_id, _), _| session_id != detached);
        }
        state.sessions = next;
        for session_id in attached {
            if let Some(session) = state.sessions.get(&session_id).cloned() {
                push_event_locked(
                    &mut state,
                    "target-attached",
                    Some(&session_id),
                    json!({
                        "targetId": session.target_id,
                        "tabId": session.tab_id,
                    }),
                );
            }
        }
        state.active_session = active_tab_id.and_then(|tab_id| {
            let tab_id = format_tab_id(tab_id);
            state
                .sessions
                .values()
                .find(|session| session.tab_id == tab_id)
                .map(|session| session.session_id.clone())
        });
        self.event_notify.notify_waiters();
    }

    pub fn active_tab_paused(&self) -> Option<Value> {
        let state = self.state.read().unwrap();
        let session_id = state.active_session.as_ref()?;
        state
            .paused_sessions
            .get(session_id)
            .map(PauseRecord::to_json)
    }

    pub fn paused_session_ids(&self) -> HashSet<String> {
        self.state
            .read()
            .unwrap()
            .paused_sessions
            .keys()
            .cloned()
            .collect()
    }

    pub fn is_fast_action(action: &str) -> bool {
        matches!(
            action,
            "debug_enable"
                | "debug_disable"
                | "debug_status"
                | "debug_stack"
                | "debug_eval"
                | "debug_pause"
                | "debug_resume"
                | "debug_step_over"
                | "debug_step_into"
                | "debug_step_out"
                | "debug_events"
                | "debug_scripts"
                | "debug_source"
                | "debug_source_search"
                | "debug_breakpoint_set"
                | "debug_breakpoint_list"
                | "debug_breakpoint_remove"
                | "debug_logpoint_set"
                | "debug_logpoint_list"
                | "debug_logpoint_remove"
        )
    }

    pub async fn execute_fast(&self, cmd: &Value) -> Value {
        let id = cmd.get("id").and_then(Value::as_str).unwrap_or("");
        let action = cmd.get("action").and_then(Value::as_str).unwrap_or("");
        if action == "confirm" {
            return self.confirm_pending(cmd).await;
        }
        if action == "deny" {
            return self.deny_pending(cmd);
        }
        if let Err(error) = validate_fast_selectors(cmd) {
            return error_response(id, &error);
        }
        match check_fast_policy(cmd) {
            FastPolicyDecision::Allow => {}
            FastPolicyDecision::Deny(error) => return error_response(id, &error),
            FastPolicyDecision::Confirm(category) => {
                *self.pending_confirmation.lock().unwrap() = Some(PendingDebugConfirmation {
                    confirmation_id: id.to_string(),
                    category: category.clone(),
                    command: cmd.clone(),
                });
                return success_response(
                    id,
                    json!({
                        "confirmation_required": true,
                        "confirmation_id": id,
                        "action": category,
                    }),
                );
            }
        }

        self.execute_authorized(cmd).await
    }

    async fn execute_authorized(&self, cmd: &Value) -> Value {
        let id = cmd.get("id").and_then(Value::as_str).unwrap_or("");
        let action = cmd.get("action").and_then(Value::as_str).unwrap_or("");

        let result = match action {
            "debug_enable" => self.enable(cmd).await,
            "debug_disable" => self.disable(cmd).await,
            "debug_status" => self.status(cmd),
            "debug_stack" => self.stack(cmd),
            "debug_eval" => self.evaluate_on_call_frame(cmd).await,
            "debug_pause" => self.control(cmd, "Debugger.pause").await,
            "debug_resume" => self.control(cmd, "Debugger.resume").await,
            "debug_step_over" => self.control(cmd, "Debugger.stepOver").await,
            "debug_step_into" => self.control(cmd, "Debugger.stepInto").await,
            "debug_step_out" => self.control(cmd, "Debugger.stepOut").await,
            "debug_events" => self.events(cmd).await,
            "debug_scripts" => self.scripts(cmd),
            "debug_source" => self.source(cmd).await,
            "debug_source_search" => self.source_search(cmd).await,
            "debug_breakpoint_set" => self.set_probe(cmd, ProbeKind::Breakpoint).await,
            "debug_breakpoint_list" => self.list_probes(ProbeKind::Breakpoint),
            "debug_breakpoint_remove" => self.remove_probe(cmd, ProbeKind::Breakpoint).await,
            "debug_logpoint_set" => self.set_probe(cmd, ProbeKind::Logpoint).await,
            "debug_logpoint_list" => self.list_probes(ProbeKind::Logpoint),
            "debug_logpoint_remove" => self.remove_probe(cmd, ProbeKind::Logpoint).await,
            _ => Err(format!("Unsupported debugger fast action: {}", action)),
        };
        match result {
            Ok(data) => success_response(id, data),
            Err(error) => error_response(id, &error),
        }
    }

    pub fn has_pending_confirmation(&self, cmd: &Value) -> bool {
        let requested = cmd.get("confirmationId").and_then(Value::as_str);
        self.pending_confirmation
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|pending| requested == Some(pending.confirmation_id.as_str()))
    }

    async fn confirm_pending(&self, cmd: &Value) -> Value {
        let id = cmd.get("id").and_then(Value::as_str).unwrap_or("");
        let requested = cmd.get("confirmationId").and_then(Value::as_str);
        let pending = {
            let mut slot = self.pending_confirmation.lock().unwrap();
            match slot.as_ref() {
                Some(pending) if requested == Some(pending.confirmation_id.as_str()) => slot.take(),
                _ => None,
            }
        };
        let Some(pending) = pending else {
            return error_response(id, "No matching pending debugger confirmation");
        };
        let result = self.execute_authorized(&pending.command).await;
        success_response(
            id,
            json!({
                "confirmed": true,
                "action": pending.category,
                "result": result,
            }),
        )
    }

    fn deny_pending(&self, cmd: &Value) -> Value {
        let id = cmd.get("id").and_then(Value::as_str).unwrap_or("");
        let requested = cmd.get("confirmationId").and_then(Value::as_str);
        let pending = {
            let mut slot = self.pending_confirmation.lock().unwrap();
            match slot.as_ref() {
                Some(pending) if requested == Some(pending.confirmation_id.as_str()) => slot.take(),
                _ => None,
            }
        };
        match pending {
            Some(pending) => {
                success_response(id, json!({ "denied": true, "action": pending.category }))
            }
            None => error_response(id, "No matching pending debugger confirmation"),
        }
    }

    async fn enable(&self, cmd: &Value) -> Result<Value, String> {
        let all_tabs = cmd.get("allTabs").and_then(Value::as_bool).unwrap_or(false);
        if all_tabs && has_session_selector(cmd) {
            return Err("Use --all-tabs or one page selector, not both".to_string());
        }
        let (client, generation, sessions) = {
            let state = self.state.read().unwrap();
            if state.engine != "chrome" {
                return Err(format!(
                    "Compiled JavaScript debugging is only supported with the Chrome engine; current engine is {}",
                    state.engine
                ));
            }
            let client = state.client.clone().ok_or("Browser not launched")?;
            let sessions = if all_tabs {
                let mut sessions: Vec<(String, String)> = state
                    .sessions
                    .values()
                    .map(|session| (session.session_id.clone(), session.tab_id.clone()))
                    .collect();
                sessions.sort_by(|a, b| a.1.cmp(&b.1));
                sessions
            } else {
                let session_id = resolve_session_id(&state, cmd)?;
                let session = state
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| format!("Unknown CDP session '{}'", session_id))?;
                vec![(session_id, session.tab_id.clone())]
            };
            (client, state.connection_generation, sessions)
        };
        if sessions.is_empty() {
            return Err("No debuggable page sessions".to_string());
        }
        let mut enabled = Vec::new();
        for (session_id, tab_id) in &sessions {
            self.state
                .write()
                .unwrap()
                .enabled_sessions
                .insert(session_id.clone());
            if let Err(error) = client
                .send_command_no_params("Runtime.enable", Some(session_id))
                .await
            {
                self.state
                    .write()
                    .unwrap()
                    .enabled_sessions
                    .remove(session_id);
                return Err(error);
            }
            let result = match client
                .send_command_no_params("Debugger.enable", Some(session_id))
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    self.state
                        .write()
                        .unwrap()
                        .enabled_sessions
                        .remove(session_id);
                    return Err(error);
                }
            };
            let _ = client
                .send_command_no_params("Page.enable", Some(session_id))
                .await;
            enabled.push(json!({
                "tabId": tab_id,
                "sessionId": session_id,
                "debuggerId": result.get("debuggerId"),
            }));
        }
        Ok(json!({
            "enabled": true,
            "connectionGeneration": generation,
            "sessions": enabled,
        }))
    }

    async fn disable(&self, cmd: &Value) -> Result<Value, String> {
        let _mutation = self.probe_mutation.lock().await;
        let resume = cmd.get("resume").and_then(Value::as_bool).unwrap_or(false);
        let all_tabs = cmd.get("allTabs").and_then(Value::as_bool).unwrap_or(false);
        if all_tabs && has_session_selector(cmd) {
            return Err("Use --all-tabs or one page selector, not both".to_string());
        }
        let (client, sessions, binding_name, binding_contexts, bound_sessions) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            let sessions = if all_tabs {
                state.enabled_sessions.iter().cloned().collect::<Vec<_>>()
            } else {
                vec![resolve_session_id(&state, cmd)?]
            };
            let binding_contexts = sessions
                .iter()
                .map(|session_id| {
                    (
                        session_id.clone(),
                        state
                            .execution_contexts
                            .get(session_id)
                            .cloned()
                            .unwrap_or_default(),
                    )
                })
                .collect::<HashMap<_, _>>();
            (
                client,
                sessions,
                state.binding_name.clone(),
                binding_contexts,
                state.binding_sessions.clone(),
            )
        };

        let paused: Vec<String> = {
            let state = self.state.read().unwrap();
            sessions
                .iter()
                .filter(|session_id| state.paused_sessions.contains_key(*session_id))
                .cloned()
                .collect()
        };
        if !paused.is_empty() && !resume {
            return Err(format!(
                "Cannot disable Debugger while {} session(s) are paused; resume them first or use `debug disable --resume`",
                paused.len()
            ));
        }
        for session_id in &paused {
            let _ = client
                .send_command_no_params("Debugger.resume", Some(session_id))
                .await;
        }
        for session_id in &sessions {
            if bound_sessions.contains(session_id) {
                let errors = remove_runtime_binding(
                    &client,
                    session_id,
                    &binding_name,
                    binding_contexts
                        .get(session_id)
                        .cloned()
                        .unwrap_or_default(),
                )
                .await;
                if !errors.is_empty() {
                    let mut state = self.state.write().unwrap();
                    push_event_locked(
                        &mut state,
                        "binding-residue",
                        Some(session_id),
                        json!({ "bindingName": binding_name, "errors": errors }),
                    );
                }
            }
            let _ = client
                .send_command_no_params("Debugger.disable", Some(session_id))
                .await;
        }
        let mut state = self.state.write().unwrap();
        for session_id in &sessions {
            invalidate_session_probes_locked(&mut state, session_id, u64::MAX, "debugger-disabled");
            state.enabled_sessions.remove(session_id);
            state.execution_contexts.remove(session_id);
            state.binding_sessions.remove(session_id);
            state.paused_sessions.remove(session_id);
            state.scripts.retain(|(sid, _), _| sid != session_id);
        }
        state.logical_probes.retain(|_, probe| {
            !probe
                .target
                .get("sessionId")
                .and_then(Value::as_str)
                .is_some_and(|session_id| sessions.iter().any(|item| item == session_id))
        });
        self.event_notify.notify_waiters();
        Ok(json!({ "disabled": true, "sessions": sessions, "resumed": paused }))
    }

    fn status(&self, cmd: &Value) -> Result<Value, String> {
        let state = self.state.read().unwrap();
        let pauses = if cmd.get("pauseId").is_some() {
            vec![resolve_pause(&state, cmd)?.to_json()]
        } else if has_session_selector(cmd) {
            let session_id = resolve_session_id(&state, cmd)?;
            state
                .paused_sessions
                .get(&session_id)
                .map(PauseRecord::to_json)
                .into_iter()
                .collect()
        } else {
            let mut values: Vec<Value> = state
                .paused_sessions
                .values()
                .map(PauseRecord::to_json)
                .collect();
            values.sort_by(|a, b| {
                a.get("pauseId")
                    .and_then(Value::as_str)
                    .cmp(&b.get("pauseId").and_then(Value::as_str))
            });
            values
        };
        let mut sessions: Vec<Value> = state
            .sessions
            .values()
            .filter(|session| {
                if has_session_selector(cmd) {
                    resolve_session_id(&state, cmd)
                        .ok()
                        .is_some_and(|selected| selected == session.session_id)
                } else {
                    true
                }
            })
            .map(|session| {
                json!({
                    "tabId": session.tab_id,
                    "targetId": session.target_id,
                    "sessionId": session.session_id,
                    "documentGeneration": session.document_generation,
                    "enabled": state.enabled_sessions.contains(&session.session_id),
                    "paused": state.paused_sessions.contains_key(&session.session_id),
                })
            })
            .collect();
        sessions.sort_by(|a, b| {
            a.get("tabId")
                .and_then(Value::as_str)
                .cmp(&b.get("tabId").and_then(Value::as_str))
        });
        Ok(json!({
            "connectionGeneration": state.connection_generation,
            "engine": state.engine,
            "enabledSessions": state.enabled_sessions.len(),
            "paused": !pauses.is_empty(),
            "pauses": pauses,
            "sessions": sessions,
        }))
    }

    fn stack(&self, cmd: &Value) -> Result<Value, String> {
        let state = self.state.read().unwrap();
        let pause = resolve_pause(&state, cmd)?;
        Ok(json!({
            "pauseId": pause.pause_id,
            "tabId": pause.tab_id,
            "sessionId": pause.session_id,
            "callFrames": pause.call_frames,
        }))
    }

    async fn evaluate_on_call_frame(&self, cmd: &Value) -> Result<Value, String> {
        let expression = cmd
            .get("expression")
            .and_then(Value::as_str)
            .ok_or("Missing debug eval expression")?;
        let (client, pause, call_frame_id) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            let pause = resolve_pause(&state, cmd)?.clone();
            let explicit = cmd.get("callFrameId").and_then(Value::as_str);
            let frame_index = cmd.get("frame").and_then(Value::as_u64).unwrap_or(0) as usize;
            if explicit.is_some() && cmd.get("frame").is_some() {
                return Err("Use either --frame or --call-frame-id, not both".to_string());
            }
            let call_frame_id = if let Some(explicit) = explicit {
                let belongs = pause.call_frames.iter().any(|frame| {
                    frame.get("callFrameId").and_then(Value::as_str) == Some(explicit)
                });
                if !belongs {
                    return Err(format!(
                        "Call frame '{}' does not belong to pause {}",
                        explicit, pause.pause_id
                    ));
                }
                explicit.to_string()
            } else {
                pause
                    .call_frames
                    .get(frame_index)
                    .and_then(|frame| frame.get("callFrameId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("Call frame index {} is out of range", frame_index))?
                    .to_string()
            };
            (client, pause, call_frame_id)
        };
        let result = client
            .send_command(
                "Debugger.evaluateOnCallFrame",
                Some(json!({
                    "callFrameId": call_frame_id,
                    "expression": expression,
                    "returnByValue": true,
                    "generatePreview": true,
                    "silent": true,
                })),
                Some(&pause.session_id),
            )
            .await?;
        Ok(json!({
            "pauseId": pause.pause_id,
            "callFrameId": call_frame_id,
            "result": result.get("result"),
            "exceptionDetails": result.get("exceptionDetails"),
        }))
    }

    async fn control(&self, cmd: &Value, method: &str) -> Result<Value, String> {
        if method == "Debugger.pause" {
            let (client, session_id, _, tab_id) = self.resolve_live_session(cmd)?;
            client
                .send_command_no_params(method, Some(&session_id))
                .await?;
            return Ok(json!({ "requested": "pause", "tabId": tab_id, "sessionId": session_id }));
        }

        let (client, pause) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            (client, resolve_pause(&state, cmd)?.clone())
        };
        client
            .send_command_no_params(method, Some(&pause.session_id))
            .await?;
        Ok(json!({
            "pauseId": pause.pause_id,
            "tabId": pause.tab_id,
            "sessionId": pause.session_id,
            "command": method,
        }))
    }

    async fn events(&self, cmd: &Value) -> Result<Value, String> {
        let since = cmd.get("since").and_then(Value::as_u64).unwrap_or(0);
        let wait_ms = cmd.get("wait").and_then(Value::as_u64).unwrap_or(0);
        if wait_ms > 0 {
            let notified = self.event_notify.notified();
            if !self.has_event_after(since) {
                let _ =
                    tokio::time::timeout(std::time::Duration::from_millis(wait_ms), notified).await;
            }
        }
        let mut state = self.state.write().unwrap();
        let events: Vec<Value> = state
            .events
            .iter()
            .filter(|event| event.get("sequence").and_then(Value::as_u64).unwrap_or(0) > since)
            .cloned()
            .collect();
        let oldest = state
            .events
            .front()
            .and_then(|event| event.get("sequence"))
            .and_then(Value::as_u64);
        let buffer_gap = state
            .dropped_through_sequence
            .is_some_and(|dropped| since <= dropped);
        let transport_gap = state
            .last_transport_gap_sequence
            .is_some_and(|sequence| sequence > since);
        let response = json!({
            "events": events,
            "oldestSequence": oldest,
            "latestSequence": state.latest_sequence,
            "gap": buffer_gap || transport_gap,
            "bufferGap": buffer_gap,
            "transportGap": transport_gap,
            "droppedThroughSequence": state.dropped_through_sequence,
            "lastTransportGapSequence": state.last_transport_gap_sequence,
        });
        if cmd.get("clear").and_then(Value::as_bool).unwrap_or(false) {
            state.events.clear();
            state.event_bytes = 0;
        }
        Ok(response)
    }

    fn scripts(&self, cmd: &Value) -> Result<Value, String> {
        let filter = cmd.get("filter").and_then(Value::as_str);
        let state = self.state.read().unwrap();
        let requested_session = if has_session_selector(cmd) {
            Some(resolve_session_id(&state, cmd)?)
        } else {
            None
        };
        let mut scripts: Vec<Value> = state
            .scripts
            .values()
            .filter(|script| {
                requested_session.as_ref().is_none_or(|session_id| {
                    script.get("sessionId").and_then(Value::as_str) == Some(session_id.as_str())
                }) && filter.is_none_or(|needle| {
                    script
                        .get("url")
                        .and_then(Value::as_str)
                        .is_some_and(|url| url.contains(needle))
                })
            })
            .cloned()
            .collect();
        scripts.sort_by(|a, b| {
            a.get("scriptId")
                .and_then(Value::as_str)
                .cmp(&b.get("scriptId").and_then(Value::as_str))
        });
        Ok(json!({
            "connectionGeneration": state.connection_generation,
            "scripts": scripts,
        }))
    }

    async fn source(&self, cmd: &Value) -> Result<Value, String> {
        let script_id = cmd
            .get("scriptId")
            .and_then(Value::as_str)
            .ok_or("Missing compiled script ID")?;
        let (client, session_id, script) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            let session_id = resolve_script_session(&state, cmd, script_id)?;
            let script = state
                .scripts
                .get(&(session_id.clone(), script_id.to_string()))
                .cloned()
                .ok_or_else(|| {
                    format!("Unknown script '{}' in session '{}'", script_id, session_id)
                })?;
            (client, session_id, script)
        };
        let result = client
            .send_command(
                "Debugger.getScriptSource",
                Some(json!({ "scriptId": script_id })),
                Some(&session_id),
            )
            .await?;
        if result
            .get("scriptSource")
            .and_then(Value::as_str)
            .is_some_and(|source| source.len() > MAX_DEBUG_SOURCE_BYTES)
        {
            return Err(format!(
                "Compiled script '{}' exceeds the {} byte source response limit; use source search instead",
                script_id, MAX_DEBUG_SOURCE_BYTES
            ));
        }
        Ok(json!({
            "script": script,
            "scriptSource": result.get("scriptSource"),
            "bytecode": result.get("bytecode"),
        }))
    }

    async fn source_search(&self, cmd: &Value) -> Result<Value, String> {
        let query = cmd
            .get("query")
            .and_then(Value::as_str)
            .ok_or("Missing source search query")?;
        if query.is_empty() {
            return Err("Source search query must not be empty".to_string());
        }
        let max_results = cmd
            .get("maxResults")
            .and_then(Value::as_u64)
            .unwrap_or(100)
            .min(1_000) as usize;
        let (client, scripts) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            let requested_session = if has_session_selector(cmd) {
                Some(resolve_session_id(&state, cmd)?)
            } else {
                None
            };
            let url_filter = cmd.get("filter").and_then(Value::as_str);
            let mut scripts: Vec<(String, String, Value)> = state
                .scripts
                .iter()
                .filter(|((session_id, _), script)| {
                    requested_session
                        .as_ref()
                        .is_none_or(|requested| requested == session_id)
                        && url_filter.is_none_or(|needle| {
                            script
                                .get("url")
                                .and_then(Value::as_str)
                                .is_some_and(|url| url.contains(needle))
                        })
                })
                .map(|((session_id, script_id), script)| {
                    (session_id.clone(), script_id.clone(), script.clone())
                })
                .collect();
            scripts.sort_by(|a, b| a.1.cmp(&b.1));
            (client, scripts)
        };

        let mut matches = Vec::new();
        let mut searched_scripts = 0_u64;
        for (session_id, script_id, script) in scripts {
            if matches.len() >= max_results {
                break;
            }
            let result = client
                .send_command(
                    "Debugger.getScriptSource",
                    Some(json!({ "scriptId": script_id })),
                    Some(&session_id),
                )
                .await?;
            let Some(source) = result.get("scriptSource").and_then(Value::as_str) else {
                continue;
            };
            searched_scripts = searched_scripts.saturating_add(1);
            for (line_index, (line_byte_offset, line)) in
                javascript_source_lines_with_offsets(source)
                    .into_iter()
                    .enumerate()
            {
                for (byte_column, _) in line.match_indices(query) {
                    let utf16_column = line[..byte_column].encode_utf16().count();
                    let query_utf16_length = query.encode_utf16().count();
                    matches.push(json!({
                        "matchIndex": matches.len() + 1,
                        "scriptId": script_id,
                        "sessionId": session_id,
                        "url": script.get("url"),
                        "line": line_index + 1,
                        "column": utf16_column + 1,
                        "endLine": line_index + 1,
                        "endColumn": utf16_column + query_utf16_length + 1,
                        "byteOffset": line_byte_offset + byte_column,
                        "context": bounded_match_context(
                            line,
                            byte_column,
                            byte_column + query.len(),
                            SOURCE_MATCH_CONTEXT_UTF16,
                        ),
                    }));
                    if matches.len() >= max_results {
                        break;
                    }
                }
                if matches.len() >= max_results {
                    break;
                }
            }
        }
        Ok(json!({
            "query": query,
            "searchedScripts": searched_scripts,
            "matches": matches,
            "truncated": matches.len() >= max_results,
        }))
    }

    async fn set_probe(&self, cmd: &Value, kind: ProbeKind) -> Result<Value, String> {
        let _mutation = self.probe_mutation.lock().await;
        let script_id = cmd
            .get("scriptId")
            .and_then(Value::as_str)
            .ok_or("Missing compiled script ID")?
            .to_string();
        let line = required_one_based(cmd, "line")?;
        let column_explicit = cmd
            .get("columnExplicit")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| cmd.get("column").is_some());
        let column = cmd.get("column").and_then(Value::as_u64).unwrap_or(1);
        if column == 0 {
            return Err("column must be one-based and greater than zero".to_string());
        }
        let mode = cmd.get("mode").and_then(Value::as_str).unwrap_or("after");
        if !matches!(
            mode,
            "strict" | "before" | "after" | "nearest" | "nearest-forward"
        ) {
            return Err(
                "Breakpoint mode must be 'strict', 'before', 'after', or 'nearest'".to_string(),
            );
        }
        let max_lines = cmd.get("maxLines").and_then(Value::as_u64).unwrap_or(3);
        if max_lines == 0 || max_lines > 500 {
            return Err("maxLines must be between 1 and 500".to_string());
        }
        let max_utf16_distance = cmd
            .get("maxUtf16Distance")
            .and_then(Value::as_u64)
            .unwrap_or(512);
        if max_utf16_distance == 0 || max_utf16_distance > 1_000_000 {
            return Err("maxUtf16Distance must be between 1 and 1000000".to_string());
        }
        let condition = cmd
            .get("condition")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let when = cmd
            .get("when")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let expression_values = cmd.get("expressions").and_then(Value::as_array);
        if expression_values.is_some_and(|items| items.iter().any(|item| !item.is_string())) {
            return Err("Every logpoint expression must be a string".to_string());
        }
        let expressions: Vec<String> = expression_values
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if kind == ProbeKind::Breakpoint && (!expressions.is_empty() || when.is_some()) {
            return Err("Breakpoint probes do not accept logpoint expressions or when".to_string());
        }
        if kind == ProbeKind::Logpoint && condition.is_some() {
            return Err("Logpoint probes use when instead of condition".to_string());
        }
        if kind == ProbeKind::Logpoint && expressions.is_empty() {
            return Err("A logpoint needs at least one --expression".to_string());
        }
        if expressions.len() > MAX_LOGPOINT_EXPRESSIONS {
            return Err(format!(
                "A logpoint supports at most {} expressions",
                MAX_LOGPOINT_EXPRESSIONS
            ));
        }

        let (
            client,
            session_id,
            generation,
            document_generation,
            script,
            binding_name,
            nonce,
            install_binding,
        ) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone().ok_or("Browser not launched")?;
            let session_id = resolve_script_session(&state, cmd, &script_id)?;
            if !state.enabled_sessions.contains(&session_id) {
                return Err(format!(
                    "Debugger is not enabled for session '{}'; run `debug enable` first",
                    session_id
                ));
            }
            let script = state
                .scripts
                .get(&(session_id.clone(), script_id.clone()))
                .cloned()
                .ok_or_else(|| {
                    format!("Unknown script '{}' in session '{}'", script_id, session_id)
                })?;
            let document_generation = state
                .sessions
                .get(&session_id)
                .map(|session| session.document_generation)
                .unwrap_or(1);
            let install_binding =
                kind == ProbeKind::Logpoint && !state.binding_sessions.contains(&session_id);
            (
                client,
                session_id,
                state.connection_generation,
                document_generation,
                script,
                state.binding_name.clone(),
                state.binding_nonce.clone(),
                install_binding,
            )
        };

        let execution_context_id = script.get("executionContextId").and_then(Value::as_u64);
        if let Some(condition) = &condition {
            validate_expression_syntax(
                &client,
                &session_id,
                execution_context_id,
                condition,
                "breakpoint condition",
            )
            .await?;
        }
        for expression in &expressions {
            validate_expression_syntax(
                &client,
                &session_id,
                execution_context_id,
                expression,
                "logpoint expression",
            )
            .await?;
        }
        if let Some(when) = &when {
            validate_expression_syntax(
                &client,
                &session_id,
                execution_context_id,
                when,
                "logpoint when expression",
            )
            .await?;
        }

        let requested_location = json!({
            "scriptId": script_id,
            "lineNumber": line - 1,
            "columnNumber": column - 1,
        });
        let source_result = client
            .send_command(
                "Debugger.getScriptSource",
                Some(json!({ "scriptId": script_id })),
                Some(&session_id),
            )
            .await?;
        let source = source_result
            .get("scriptSource")
            .and_then(Value::as_str)
            .ok_or("Chrome did not return compiled script source")?;
        let source_lines = javascript_source_lines(source);
        let last_line = source_lines.len().saturating_sub(1) as u64;
        let bounded_last_line = line
            .saturating_sub(1)
            .saturating_add(max_lines)
            .min(last_line);
        let (end_line, end_column) = if bounded_last_line < last_line {
            (bounded_last_line.saturating_add(1), 0)
        } else {
            (
                last_line,
                source_lines
                    .last()
                    .map(|line| line.encode_utf16().count() as u64)
                    .unwrap_or(0),
            )
        };
        let query_end = json!({
            "scriptId": script_id,
            "lineNumber": end_line,
            "columnNumber": end_column,
        });
        let possible = client
            .send_command(
                "Debugger.getPossibleBreakpoints",
                Some(json!({
                    "start": requested_location,
                    "end": query_end,
                    "restrictToFunction": true,
                })),
                Some(&session_id),
            )
            .await?;
        let mut locations = possible
            .get("locations")
            .and_then(Value::as_array)
            .cloned()
            .ok_or("Chrome did not return possible breakpoint locations")?;

        // CDP only returns locations at or after its start position. For a
        // backward candidate, prove function identity by starting a second
        // restricted query at that candidate and requiring it to reach an
        // anchor already known to be in the requested function. If no anchor
        // exists, fail conservatively instead of crossing a function boundary.
        if matches!(mode, "before" | "nearest") {
            let requested_offset = utf16_offset_for_location(
                source,
                line.saturating_sub(1) as usize,
                column.saturating_sub(1) as usize,
            )
            .ok_or_else(|| {
                format!(
                    "Requested compiled JavaScript location {}:{} is outside the script",
                    line, column
                )
            })? as u64;
            let backward_start_line = line.saturating_sub(1).saturating_sub(max_lines);
            let backward = client
                .send_command(
                    "Debugger.getPossibleBreakpoints",
                    Some(json!({
                        "start": {
                            "scriptId": script_id,
                            "lineNumber": backward_start_line,
                            "columnNumber": 0,
                        },
                        "end": requested_location,
                        "restrictToFunction": false,
                    })),
                    Some(&session_id),
                )
                .await?;
            let anchor = locations.first().cloned();
            if let Some(anchor) = anchor {
                let candidates: Vec<Value> = backward
                    .get("locations")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|candidate| {
                        let candidate_line = candidate
                            .get("lineNumber")
                            .and_then(Value::as_u64)
                            .unwrap_or(u64::MAX);
                        let candidate_column = candidate
                            .get("columnNumber")
                            .and_then(Value::as_u64)
                            .unwrap_or(0);
                        utf16_offset_for_location(
                            source,
                            candidate_line as usize,
                            candidate_column as usize,
                        )
                        .map(|offset| {
                            let offset = offset as u64;
                            offset < requested_offset
                                && requested_offset.abs_diff(offset) <= max_utf16_distance
                                && candidate_line.abs_diff(line.saturating_sub(1)) <= max_lines
                        })
                        .unwrap_or(false)
                    })
                    .cloned()
                    .collect();
                for candidate in candidates
                    .into_iter()
                    .rev()
                    .take(MAX_BREAKPOINT_VERIFICATION_CANDIDATES)
                {
                    let verification = client
                        .send_command(
                            "Debugger.getPossibleBreakpoints",
                            Some(json!({
                                "start": candidate,
                                "end": query_end,
                                "restrictToFunction": true,
                            })),
                            Some(&session_id),
                        )
                        .await?;
                    let same_function = verification
                        .get("locations")
                        .and_then(Value::as_array)
                        .is_some_and(|verified| {
                            verified
                                .iter()
                                .any(|location| same_cdp_location(location, &anchor))
                        });
                    if same_function {
                        locations.push(candidate);
                    }
                }
            }
        }
        let (actual_location, resolution_reason, utf16_distance) = select_breakpoint_location(
            &locations,
            BreakpointResolutionRequest {
                line,
                column,
                column_explicit,
                mode,
                max_lines,
                max_utf16_distance,
            },
            source,
        )?;

        let probe_id = cmd
            .get("rebindProbeId")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                format!(
                    "probe-{}-{}",
                    generation,
                    NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed)
                )
            });
        let physical_id = format!(
            "physical-{}-{}",
            generation,
            NEXT_PROBE_ID.fetch_add(1, Ordering::Relaxed)
        );
        let cdp_condition = if kind == ProbeKind::Logpoint {
            build_logpoint_condition(
                &binding_name,
                &nonce,
                &probe_id,
                &physical_id,
                when.as_deref(),
                &expressions,
            )?
        } else {
            condition.clone().unwrap_or_default()
        };
        if install_binding {
            client
                .send_command(
                    "Runtime.addBinding",
                    Some(json!({ "name": binding_name })),
                    Some(&session_id),
                )
                .await?;
            self.state
                .write()
                .unwrap()
                .binding_sessions
                .insert(session_id.clone());
        }
        let result = match client
            .send_command(
                "Debugger.setBreakpoint",
                Some(json!({
                    "location": actual_location,
                    "condition": cdp_condition,
                })),
                Some(&session_id),
            )
            .await
        {
            Ok(result) => result,
            Err(error) => {
                if install_binding {
                    let cleanup_errors = self
                        .cleanup_binding_installation(
                            &client,
                            &session_id,
                            &binding_name,
                            generation,
                        )
                        .await;
                    if !cleanup_errors.is_empty() {
                        return Err(format!(
                            "{}; Runtime binding cleanup also failed: {}",
                            error,
                            cleanup_errors.join("; ")
                        ));
                    }
                }
                return Err(error);
            }
        };
        let cdp_breakpoint_id = match result.get("breakpointId").and_then(Value::as_str) {
            Some(breakpoint_id) => breakpoint_id.to_string(),
            None => {
                if install_binding {
                    let _ = self
                        .cleanup_binding_installation(
                            &client,
                            &session_id,
                            &binding_name,
                            generation,
                        )
                        .await;
                }
                return Err("Chrome did not return a breakpoint ID".to_string());
            }
        };
        let resolved_location = result
            .get("actualLocation")
            .cloned()
            .unwrap_or_else(|| actual_location.clone());
        let tags = cmd
            .get("tags")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let persistent = cmd.get("persist").and_then(Value::as_bool).unwrap_or(false);
        let owner = script.get("runtimeOwner").cloned().unwrap_or(Value::Null);
        let status = if persistent
            && owner
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| matches!(status, "unknown" | "ambiguous"))
        {
            "bound-awaiting-owner-evidence"
        } else {
            "bound"
        };
        let target = json!({
            "connectionGeneration": generation,
            "sessionId": session_id,
            "documentGeneration": document_generation,
            "scriptId": script_id,
            "url": script.get("url"),
            "executionContextId": execution_context_id,
            "runtimeOwner": owner,
            "requestedLine": line,
            "requestedColumn": column,
            "columnExplicit": column_explicit,
            "mode": mode,
            "maxLines": max_lines,
            "maxUtf16Distance": max_utf16_distance,
            "resolutionReason": resolution_reason,
            "utf16Distance": utf16_distance,
        });
        let requested_location_external = one_based_location(&requested_location);
        let resolved_location_external = one_based_location(&resolved_location);
        let physical = PhysicalProbe {
            physical_id: physical_id.clone(),
            cdp_breakpoint_id: cdp_breakpoint_id.clone(),
            probe_id: probe_id.clone(),
            connection_generation: generation,
            session_id: session_id.clone(),
            document_generation,
            script_id: script_id.clone(),
            execution_context_id,
            requested_location: requested_location_external,
            actual_location: resolved_location_external,
        };
        let logical = LogicalProbe {
            probe_id: probe_id.clone(),
            kind,
            enabled: true,
            persistent,
            status: status.to_string(),
            condition,
            when,
            expressions,
            tags,
            target,
            physical_ids: vec![physical_id.clone()],
        };
        let response = {
            let mut state = self.state.write().unwrap();
            if state.connection_generation != generation
                || state
                    .sessions
                    .get(&session_id)
                    .is_none_or(|session| session.document_generation != document_generation)
                || !state
                    .scripts
                    .contains_key(&(session_id.clone(), script_id.clone()))
            {
                None
            } else {
                state
                    .physical_by_cdp_breakpoint
                    .insert(cdp_breakpoint_id.clone(), physical_id.clone());
                state
                    .physical_probes
                    .insert(physical_id.clone(), physical.clone());
                if let Some(existing) = state.logical_probes.get_mut(&probe_id) {
                    existing.physical_ids.push(physical_id.clone());
                    existing.status = "rebound".to_string();
                } else {
                    state
                        .logical_probes
                        .insert(probe_id.clone(), logical.clone());
                }
                let response = state
                    .logical_probes
                    .get(&probe_id)
                    .expect("logical probe inserted")
                    .to_json(&state.physical_probes);
                push_event_locked(
                    &mut state,
                    "probe-bound",
                    Some(&session_id),
                    json!({
                        "probe": response,
                        "resolutionReason": resolution_reason,
                        "utf16Distance": utf16_distance,
                    }),
                );
                Some(response)
            }
        };
        let Some(response) = response else {
            let _ = client
                .send_command(
                    "Debugger.removeBreakpoint",
                    Some(json!({ "breakpointId": cdp_breakpoint_id })),
                    Some(&session_id),
                )
                .await;
            if install_binding {
                let _ = self
                    .cleanup_binding_installation(&client, &session_id, &binding_name, generation)
                    .await;
            }
            return Err("Browser connection changed while setting the probe".to_string());
        };
        self.event_notify.notify_waiters();
        Ok(response)
    }

    async fn cleanup_binding_installation(
        &self,
        client: &CdpClient,
        session_id: &str,
        binding_name: &str,
        generation: u64,
    ) -> Vec<String> {
        let contexts = {
            let state = self.state.read().unwrap();
            if state.connection_generation == generation && state.binding_name == binding_name {
                state
                    .execution_contexts
                    .get(session_id)
                    .cloned()
                    .unwrap_or_default()
            } else {
                HashSet::new()
            }
        };
        let errors = remove_runtime_binding(client, session_id, binding_name, contexts).await;
        let mut state = self.state.write().unwrap();
        if state.connection_generation == generation && state.binding_name == binding_name {
            state.binding_sessions.remove(session_id);
        }
        errors
    }

    async fn reconcile_persistent_probes(
        &self,
        generation: u64,
        session_id: &str,
        script_id: &str,
    ) {
        let candidates: Vec<RebindCandidate> = {
            let mut state = self.state.write().unwrap();
            if state.connection_generation != generation {
                return;
            }
            let Some(script) = state
                .scripts
                .get(&(session_id.to_string(), script_id.to_string()))
                .cloned()
            else {
                return;
            };
            let Some(session) = state.sessions.get(session_id) else {
                return;
            };
            let owner = script.get("runtimeOwner").cloned().unwrap_or(Value::Null);
            let resolved_owner = owner
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "resolved");
            if !resolved_owner {
                for probe in state.logical_probes.values_mut().filter(|probe| {
                    probe.persistent
                        && probe.enabled
                        && probe.target.get("sessionId").and_then(Value::as_str) == Some(session_id)
                        && probe.target.get("url") == script.get("url")
                }) {
                    probe.status = "awaiting-owner-evidence".to_string();
                }
                return;
            }
            let owner_id = owner.get("ownerId");
            state
                .logical_probes
                .values()
                .filter(|probe| {
                    probe.persistent
                        && probe.enabled
                        && probe.target.get("sessionId").and_then(Value::as_str) == Some(session_id)
                        && probe
                            .target
                            .get("documentGeneration")
                            .and_then(Value::as_u64)
                            == Some(session.document_generation)
                        && probe.target.get("url") == script.get("url")
                        && probe
                            .target
                            .get("runtimeOwner")
                            .and_then(|runtime_owner| runtime_owner.get("ownerId"))
                            == owner_id
                        && probe.target.get("executionContextId")
                            == script.get("executionContextId")
                        && !probe.physical_ids.iter().any(|physical_id| {
                            state
                                .physical_probes
                                .get(physical_id)
                                .is_some_and(|binding| binding.script_id == script_id)
                        })
                })
                .map(|probe| {
                    (
                        probe.probe_id.clone(),
                        probe.kind,
                        probe.target.clone(),
                        probe.condition.clone(),
                        probe.when.clone(),
                        probe.expressions.clone(),
                        Value::Object(probe.tags.clone()),
                    )
                })
                .collect()
        };

        for (probe_id, kind, target, condition, when, expressions, tags) in candidates {
            let mut command = json!({
                "scriptId": script_id,
                "sessionId": session_id,
                "line": target.get("requestedLine"),
                "column": target.get("requestedColumn"),
                "columnExplicit": target.get("columnExplicit"),
                "mode": target.get("mode"),
                "maxLines": target.get("maxLines"),
                "maxUtf16Distance": target.get("maxUtf16Distance"),
                "persist": true,
                "condition": condition,
                "when": when,
                "expressions": expressions,
                "tags": tags,
                "rebindProbeId": probe_id,
            });
            if condition.is_none() {
                command.as_object_mut().unwrap().remove("condition");
            }
            if when.is_none() {
                command.as_object_mut().unwrap().remove("when");
            }
            if let Err(error) = self.set_probe(&command, kind).await {
                let mut state = self.state.write().unwrap();
                if let Some(probe) = state.logical_probes.get_mut(&probe_id) {
                    probe.status = "rebind-failed".to_string();
                }
                push_event_locked(
                    &mut state,
                    "probe-rebind-failed",
                    Some(session_id),
                    json!({ "probeId": probe_id, "scriptId": script_id, "error": error }),
                );
                self.event_notify.notify_waiters();
            }
        }
    }

    fn list_probes(&self, kind: ProbeKind) -> Result<Value, String> {
        let state = self.state.read().unwrap();
        let mut probes: Vec<Value> = state
            .logical_probes
            .values()
            .filter(|probe| probe.kind == kind)
            .map(|probe| probe.to_json(&state.physical_probes))
            .collect();
        probes.sort_by(|a, b| {
            a.get("probeId")
                .and_then(Value::as_str)
                .cmp(&b.get("probeId").and_then(Value::as_str))
        });
        Ok(json!({ "kind": kind.as_str(), "probes": probes }))
    }

    async fn remove_probe(&self, cmd: &Value, kind: ProbeKind) -> Result<Value, String> {
        let _mutation = self.probe_mutation.lock().await;
        let probe_id = cmd
            .get("probeId")
            .and_then(Value::as_str)
            .ok_or("Missing probe ID")?
            .to_string();
        let (client, probe, physical, binding_name) = {
            let state = self.state.read().unwrap();
            let client = state.client.clone();
            let probe = state
                .logical_probes
                .get(&probe_id)
                .filter(|probe| probe.kind == kind)
                .cloned()
                .ok_or_else(|| format!("Unknown {} '{}'", kind.as_str(), probe_id))?;
            let physical = probe
                .physical_ids
                .iter()
                .filter_map(|id| state.physical_probes.get(id).cloned())
                .collect::<Vec<_>>();
            (client, probe, physical, state.binding_name.clone())
        };
        let mut errors = Vec::new();
        for binding in &physical {
            if let Some(client) = &client {
                if let Err(error) = client
                    .send_command(
                        "Debugger.removeBreakpoint",
                        Some(json!({ "breakpointId": binding.cdp_breakpoint_id })),
                        Some(&binding.session_id),
                    )
                    .await
                {
                    errors.push(error);
                }
            }
        }
        let binding_cleanup_session = {
            let mut state = self.state.write().unwrap();
            state.logical_probes.remove(&probe_id);
            for binding in &physical {
                state.physical_probes.remove(&binding.physical_id);
                state
                    .physical_by_cdp_breakpoint
                    .remove(&binding.cdp_breakpoint_id);
            }
            let removed = probe.to_json(&state.physical_probes);
            let session_id = physical
                .first()
                .map(|binding| binding.session_id.as_str())
                .or_else(|| probe.target.get("sessionId").and_then(Value::as_str));
            push_event_locked(
                &mut state,
                "probe-removed",
                session_id,
                json!({ "probe": removed, "cleanupErrors": errors }),
            );
            if kind == ProbeKind::Logpoint {
                session_id.map(ToString::to_string).filter(|session_id| {
                    !state.logical_probes.values().any(|remaining| {
                        remaining.kind == ProbeKind::Logpoint
                            && remaining.target.get("sessionId").and_then(Value::as_str)
                                == Some(session_id.as_str())
                    })
                })
            } else {
                None
            }
        };
        if let Some(session_id) = binding_cleanup_session {
            let contexts = self
                .state
                .read()
                .unwrap()
                .execution_contexts
                .get(&session_id)
                .cloned()
                .unwrap_or_default();
            let cleanup_errors = if let Some(client) = &client {
                remove_runtime_binding(client, &session_id, &binding_name, contexts).await
            } else {
                Vec::new()
            };
            self.state
                .write()
                .unwrap()
                .binding_sessions
                .remove(&session_id);
            if !cleanup_errors.is_empty() {
                let mut state = self.state.write().unwrap();
                push_event_locked(
                    &mut state,
                    "binding-residue",
                    Some(&session_id),
                    json!({ "bindingName": binding_name, "errors": cleanup_errors }),
                );
                errors.extend(cleanup_errors);
            }
        }
        self.event_notify.notify_waiters();
        Ok(json!({
            "removed": true,
            "probeId": probe_id,
            "cleanupErrors": errors,
        }))
    }

    fn resolve_live_session(
        &self,
        cmd: &Value,
    ) -> Result<(Arc<CdpClient>, String, u64, String), String> {
        let state = self.state.read().unwrap();
        let client = state.client.clone().ok_or("Browser not launched")?;
        let session_id = resolve_session_id(&state, cmd)?;
        let session = state
            .sessions
            .get(&session_id)
            .ok_or_else(|| format!("Unknown CDP session '{}'", session_id))?;
        Ok((
            client,
            session_id,
            state.connection_generation,
            session.tab_id.clone(),
        ))
    }

    fn has_event_after(&self, since: u64) -> bool {
        self.state.read().unwrap().latest_sequence > since
    }

    fn handle_event(&self, generation: u64, event: CdpEvent) {
        let mut state = self.state.write().unwrap();
        if state.connection_generation != generation || state.client.is_none() {
            return;
        }
        match event.method.as_str() {
            "Debugger.scriptParsed" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                if !state.enabled_sessions.contains(session_id) {
                    return;
                }
                let script_id = event
                    .params
                    .get("scriptId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if script_id.is_empty() {
                    return;
                }
                let session = state.sessions.get(session_id);
                let owner = runtime_owner(&event.params);
                let rebindable = owner.get("status").and_then(Value::as_str) == Some("resolved")
                    && owner.get("confidence").and_then(Value::as_str) == Some("high");
                let script = json!({
                    "connectionGeneration": generation,
                    "tabId": session.map(|s| s.tab_id.clone()),
                    "targetId": session.map(|s| s.target_id.clone()),
                    "sessionId": session_id,
                    "documentGeneration": session.map(|s| s.document_generation).unwrap_or(1),
                    "scriptId": script_id,
                    "executionContextId": event.params.get("executionContextId"),
                    "executionContextAuxData": event.params.get("executionContextAuxData"),
                    "url": event.params.get("url"),
                    "hash": event.params.get("hash"),
                    "hasSourceURL": event.params.get("hasSourceURL"),
                    "sourceMapURL": event.params.get("sourceMapURL"),
                    "isModule": event.params.get("isModule"),
                    "startLine": one_based(event.params.get("startLine")),
                    "startColumn": one_based(event.params.get("startColumn")),
                    "endLine": one_based(event.params.get("endLine")),
                    "endColumn": one_based(event.params.get("endColumn")),
                    "scriptInstanceKey": {
                        "connectionGeneration": generation,
                        "sessionId": session_id,
                        "documentGeneration": session.map(|s| s.document_generation).unwrap_or(1),
                        "scriptId": script_id,
                    },
                    "sourceLineageKey": {
                        "sessionId": session_id,
                        "documentGeneration": session.map(|s| s.document_generation).unwrap_or(1),
                        "executionContextId": event.params.get("executionContextId"),
                        "url": event.params.get("url"),
                        "resolvedRuntimeOwnerId": owner.get("ownerId"),
                    },
                    "rebindable": rebindable,
                    "runtimeOwner": owner,
                    "initiatorEvidence": {
                        "scriptParsedStackTrace": event.params.get("stackTrace"),
                    },
                });
                state
                    .scripts
                    .insert((session_id.to_string(), script_id), script.clone());
                push_event_locked(&mut state, "script-parsed", Some(session_id), script);
            }
            "Debugger.paused" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                let Some(session) = state.sessions.get(session_id).cloned() else {
                    return;
                };
                let sequence = state.latest_sequence.saturating_add(1);
                let hit_breakpoints: Vec<String> = event
                    .params
                    .get("hitBreakpoints")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut probe_ids: Vec<String> = hit_breakpoints
                    .iter()
                    .filter_map(|breakpoint_id| {
                        let physical_id = state.physical_by_cdp_breakpoint.get(breakpoint_id)?;
                        state
                            .physical_probes
                            .get(physical_id)
                            .map(|physical| physical.probe_id.clone())
                    })
                    .collect();
                probe_ids.sort();
                probe_ids.dedup();
                let pause = PauseRecord {
                    pause_id: format!("pause-{}-{}", generation, sequence),
                    connection_generation: generation,
                    tab_id: session.tab_id,
                    session_id: session_id.to_string(),
                    document_generation: session.document_generation,
                    reason: event
                        .params
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("other")
                        .to_string(),
                    hit_breakpoints,
                    probe_ids,
                    call_frames: event
                        .params
                        .get("callFrames")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default(),
                    data: event.params.get("data").cloned(),
                };
                state
                    .paused_sessions
                    .insert(session_id.to_string(), pause.clone());
                push_event_locked(
                    &mut state,
                    "debugger-paused",
                    Some(session_id),
                    pause.to_json(),
                );
            }
            "Debugger.resumed" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                let pause = state
                    .paused_sessions
                    .remove(session_id)
                    .map(|p| p.to_json());
                push_event_locked(
                    &mut state,
                    "debugger-resumed",
                    Some(session_id),
                    json!({ "pause": pause }),
                );
            }
            "Runtime.executionContextCreated" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                let context = event.params.get("context");
                let context_id = context
                    .and_then(|context| context.get("id"))
                    .and_then(Value::as_u64);
                if let Some(context_id) = context_id {
                    state
                        .execution_contexts
                        .entry(session_id.to_string())
                        .or_default()
                        .insert(context_id);
                }
                push_event_locked(
                    &mut state,
                    "execution-context-created",
                    Some(session_id),
                    json!({
                        "executionContextId": context_id,
                        "name": context.and_then(|context| context.get("name")),
                        "origin": context.and_then(|context| context.get("origin")),
                        "auxData": context.and_then(|context| context.get("auxData")),
                    }),
                );
            }
            "Runtime.executionContextDestroyed" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                let context_id = event
                    .params
                    .get("executionContextId")
                    .and_then(Value::as_u64);
                if let Some(context_id) = context_id {
                    if let Some(contexts) = state.execution_contexts.get_mut(session_id) {
                        contexts.remove(&context_id);
                    }
                    state.scripts.retain(|(sid, _), script| {
                        sid != session_id
                            || script.get("executionContextId").and_then(Value::as_u64)
                                != Some(context_id)
                    });
                    invalidate_context_probes_locked(
                        &mut state,
                        session_id,
                        context_id,
                        "execution-context-destroyed",
                    );
                }
                push_event_locked(
                    &mut state,
                    "execution-context-destroyed",
                    Some(session_id),
                    json!({ "executionContextId": context_id }),
                );
            }
            "Runtime.executionContextsCleared" => {
                if let Some(session_id) = event.session_id.as_deref() {
                    let generation = state
                        .sessions
                        .get(session_id)
                        .map(|session| session.document_generation)
                        .unwrap_or(1);
                    state.execution_contexts.remove(session_id);
                    state.scripts.retain(|(sid, _), _| sid != session_id);
                    state.paused_sessions.remove(session_id);
                    invalidate_session_probes_locked(
                        &mut state,
                        session_id,
                        generation,
                        "execution-contexts-cleared",
                    );
                    push_event_locked(
                        &mut state,
                        "execution-contexts-cleared",
                        Some(session_id),
                        json!({}),
                    );
                }
            }
            "Runtime.bindingCalled" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                if event.params.get("name").and_then(Value::as_str)
                    != Some(state.binding_name.as_str())
                {
                    return;
                }
                let execution_context_id = event
                    .params
                    .get("executionContextId")
                    .and_then(Value::as_u64);
                let raw_payload = event.params.get("payload").and_then(Value::as_str);
                if raw_payload.is_some_and(|payload| payload.len() > MAX_LOGPOINT_PAYLOAD_BYTES) {
                    push_event_locked(
                        &mut state,
                        "logpoint-rejected",
                        Some(session_id),
                        json!({ "reason": "payload-too-large" }),
                    );
                    self.event_notify.notify_waiters();
                    return;
                }
                let payload =
                    raw_payload.and_then(|payload| serde_json::from_str::<Value>(payload).ok());
                let Some(payload) = payload else {
                    push_event_locked(
                        &mut state,
                        "logpoint-rejected",
                        Some(session_id),
                        json!({ "reason": "invalid-json-payload" }),
                    );
                    self.event_notify.notify_waiters();
                    return;
                };
                let nonce_matches = payload.get("nonce").and_then(Value::as_str)
                    == Some(state.binding_nonce.as_str());
                let probe_id = payload.get("probeId").and_then(Value::as_str);
                let physical_id = payload.get("physicalBindingId").and_then(Value::as_str);
                let binding = physical_id
                    .and_then(|id| state.physical_probes.get(id))
                    .cloned();
                let valid =
                    nonce_matches
                        && binding.as_ref().is_some_and(|binding| {
                            Some(binding.probe_id.as_str()) == probe_id
                                && binding.connection_generation == generation
                                && binding.session_id == session_id
                                && (binding.execution_context_id.is_none()
                                    || binding.execution_context_id == execution_context_id)
                                && state.logical_probes.get(&binding.probe_id).is_some_and(
                                    |probe| probe.kind == ProbeKind::Logpoint && probe.enabled,
                                )
                        });
                if !valid {
                    push_event_locked(
                        &mut state,
                        "logpoint-rejected",
                        Some(session_id),
                        json!({
                            "reason": "binding-validation-failed",
                            "executionContextId": execution_context_id,
                        }),
                    );
                    self.event_notify.notify_waiters();
                    return;
                }
                let binding = binding.unwrap();
                let tags = state
                    .logical_probes
                    .get(&binding.probe_id)
                    .map(|probe| probe.tags.clone())
                    .unwrap_or_default();
                push_event_locked(
                    &mut state,
                    "logpoint-hit",
                    Some(session_id),
                    json!({
                        "probeId": binding.probe_id,
                        "physicalBindingId": binding.physical_id,
                        "scriptId": binding.script_id,
                        "documentGeneration": binding.document_generation,
                        "location": binding.actual_location,
                        "tags": tags,
                        "executionContextId": execution_context_id,
                        "values": payload.get("values"),
                        "whenError": payload.get("whenError"),
                        "serializationError": payload.get("serializationError"),
                    }),
                );
            }
            "Page.frameNavigated" => {
                let Some(session_id) = event.session_id.as_deref() else {
                    return;
                };
                let Some(frame) = event.params.get("frame") else {
                    return;
                };
                if frame.get("parentId").is_some() {
                    return;
                }
                let loader_id = frame
                    .get("loaderId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let Some((previous_loader, previous_generation, generation_now)) =
                    state.sessions.get_mut(session_id).map(|session| {
                        let previous_loader = session.loader_id.clone();
                        let previous_generation = session.document_generation;
                        if previous_loader.is_some() && previous_loader != loader_id {
                            session.document_generation =
                                session.document_generation.saturating_add(1);
                        }
                        session.loader_id = loader_id.clone();
                        (
                            previous_loader,
                            previous_generation,
                            session.document_generation,
                        )
                    })
                else {
                    return;
                };
                if previous_loader.is_some() && previous_loader != loader_id {
                    push_event_locked(
                        &mut state,
                        "document-invalidated",
                        Some(session_id),
                        json!({
                            "loaderId": previous_loader,
                            "documentGeneration": previous_generation,
                        }),
                    );
                    state.scripts.retain(|(sid, _), _| sid != session_id);
                    state.paused_sessions.remove(session_id);
                    invalidate_session_probes_locked(
                        &mut state,
                        session_id,
                        previous_generation,
                        "document-invalidated",
                    );
                }
                push_event_locked(
                    &mut state,
                    "document-committed",
                    Some(session_id),
                    json!({
                        "previousLoaderId": previous_loader,
                        "loaderId": loader_id,
                        "previousDocumentGeneration": previous_generation,
                        "documentGeneration": generation_now,
                        "url": frame.get("url"),
                    }),
                );
            }
            "Target.detachedFromTarget" => {
                if let Some(detached) = event.params.get("sessionId").and_then(Value::as_str) {
                    let pause = state.paused_sessions.remove(detached).map(|p| p.to_json());
                    push_event_locked(
                        &mut state,
                        "target-detached",
                        Some(detached),
                        json!({ "invalidatedPause": pause }),
                    );
                    state.sessions.remove(detached);
                    state.enabled_sessions.remove(detached);
                    state.execution_contexts.remove(detached);
                    state.binding_sessions.remove(detached);
                    state.scripts.retain(|(sid, _), _| sid != detached);
                    invalidate_session_probes_locked(
                        &mut state,
                        detached,
                        u64::MAX,
                        "session-detached",
                    );
                    push_event_locked(&mut state, "session-detached", Some(detached), json!({}));
                }
            }
            _ => return,
        }
        self.event_notify.notify_waiters();
    }

    fn record_transport_gap(&self, generation: u64, count: u64) {
        let mut state = self.state.write().unwrap();
        if state.connection_generation != generation {
            return;
        }
        push_event_locked(
            &mut state,
            "transport-gap",
            None,
            json!({ "gapReason": "broadcast-lag", "droppedEventCount": count }),
        );
        state.last_transport_gap_sequence = Some(state.latest_sequence);
        self.event_notify.notify_waiters();
    }
}

async fn remove_runtime_binding(
    client: &CdpClient,
    session_id: &str,
    binding_name: &str,
    execution_contexts: HashSet<u64>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let binding_literal = match serde_json::to_string(binding_name) {
        Ok(value) => value,
        Err(error) => {
            errors.push(error.to_string());
            return errors;
        }
    };
    let expression = format!(
        "(()=>{{try{{return delete globalThis[{}]}}catch(_){{return false}}}})()",
        binding_literal
    );
    if execution_contexts.is_empty() {
        if let Err(error) = client
            .send_command(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expression,
                    "returnByValue": true,
                    "silent": true,
                })),
                Some(session_id),
            )
            .await
        {
            errors.push(error);
        }
    } else {
        for context_id in execution_contexts {
            if let Err(error) = client
                .send_command(
                    "Runtime.evaluate",
                    Some(json!({
                        "expression": expression,
                        "contextId": context_id,
                        "returnByValue": true,
                        "silent": true,
                    })),
                    Some(session_id),
                )
                .await
            {
                errors.push(format!("context {}: {}", context_id, error));
            }
        }
    }
    if let Err(error) = client
        .send_command(
            "Runtime.removeBinding",
            Some(json!({ "name": binding_name })),
            Some(session_id),
        )
        .await
    {
        errors.push(error);
    }
    errors
}

fn has_session_selector(cmd: &Value) -> bool {
    cmd.get("sessionId").is_some() || cmd.get("tabId").is_some()
}

fn resolve_script_session(
    state: &ControllerState,
    cmd: &Value,
    script_id: &str,
) -> Result<String, String> {
    if has_session_selector(cmd) {
        let session_id = resolve_session_id(state, cmd)?;
        if state
            .scripts
            .contains_key(&(session_id.clone(), script_id.to_string()))
        {
            return Ok(session_id);
        }
        return Err(format!(
            "Unknown script '{}' in session '{}'",
            script_id, session_id
        ));
    }
    let matching_sessions: Vec<String> = state
        .scripts
        .keys()
        .filter(|(_, candidate_script_id)| candidate_script_id == script_id)
        .map(|(session_id, _)| session_id.clone())
        .collect();
    match matching_sessions.len() {
        0 => Err(format!("Unknown compiled script ID '{}'", script_id)),
        1 => Ok(matching_sessions[0].clone()),
        count => {
            if let Some(active) = state.active_session.as_ref() {
                if matching_sessions.contains(active) {
                    return Ok(active.clone());
                }
            }
            Err(format!(
                "Script ID '{}' exists in {} sessions; specify --tab or --session",
                script_id, count
            ))
        }
    }
}

fn required_one_based(cmd: &Value, key: &str) -> Result<u64, String> {
    let value = cmd
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("Missing {}", key))?;
    if value == 0 {
        return Err(format!("{} must be one-based and greater than zero", key));
    }
    Ok(value)
}

fn select_breakpoint_location(
    locations: &[Value],
    request: BreakpointResolutionRequest<'_>,
    source: &str,
) -> Result<(Value, String, u64), String> {
    let BreakpointResolutionRequest {
        line: requested_line,
        column: requested_column,
        column_explicit,
        mode,
        max_lines,
        max_utf16_distance,
    } = request;
    let requested_line_zero = requested_line - 1;
    let requested_column_zero = requested_column - 1;
    let requested_offset = utf16_offset_for_location(
        source,
        requested_line_zero as usize,
        requested_column_zero as usize,
    )
    .ok_or_else(|| {
        format!(
            "Requested compiled JavaScript location {}:{} is outside the script",
            requested_line, requested_column
        )
    })? as u64;
    let canonical_mode = if mode == "nearest-forward" {
        "after"
    } else {
        mode
    };
    let mut candidates: Vec<(u64, bool, &Value)> = locations
        .iter()
        .filter_map(|location| {
            let line = location.get("lineNumber").and_then(Value::as_u64)?;
            let column = location
                .get("columnNumber")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if line.abs_diff(requested_line_zero) > max_lines {
                return None;
            }
            let offset = utf16_offset_for_location(source, line as usize, column as usize)? as u64;
            let distance = offset.abs_diff(requested_offset);
            if distance > max_utf16_distance {
                return None;
            }
            let after = offset >= requested_offset;
            let accepted = match canonical_mode {
                "strict" => {
                    line == requested_line_zero
                        && (!column_explicit || column == requested_column_zero)
                }
                "before" => offset <= requested_offset,
                "after" => after,
                "nearest" => true,
                _ => false,
            };
            accepted.then_some((distance, after, location))
        })
        .collect();
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
    let Some((distance, after, selected)) = candidates.first().copied() else {
        return Err(format!(
            "No breakable compiled JavaScript location found for {}:{} in '{}' mode within {} line(s) and {} UTF-16 code units",
            requested_line, requested_column, canonical_mode, max_lines, max_utf16_distance
        ));
    };
    let reason = if distance == 0 {
        "exact"
    } else if canonical_mode == "strict" && !column_explicit {
        "first-breakable-on-requested-line"
    } else if after {
        "nearest-after-within-function"
    } else {
        "nearest-before-within-function"
    };
    Ok((selected.clone(), reason.to_string(), distance))
}

fn utf16_offset_for_location(source: &str, target_line: usize, column: usize) -> Option<usize> {
    let units: Vec<u16> = source.encode_utf16().collect();
    let mut line_starts = vec![0_usize];
    let mut index = 0_usize;
    while index < units.len() {
        match units[index] {
            0x000d => {
                index += 1;
                if units.get(index) == Some(&0x000a) {
                    index += 1;
                }
                line_starts.push(index);
            }
            0x000a | 0x2028 | 0x2029 => {
                index += 1;
                line_starts.push(index);
            }
            _ => index += 1,
        }
    }
    let start = *line_starts.get(target_line)?;
    let end = line_starts
        .get(target_line + 1)
        .copied()
        .unwrap_or(units.len());
    let content_end = if target_line + 1 < line_starts.len() {
        let mut end = end;
        if end > start && matches!(units[end - 1], 0x000a | 0x000d | 0x2028 | 0x2029) {
            end -= 1;
            if end > start && units[end - 1] == 0x000d && units.get(end) == Some(&0x000a) {
                end -= 1;
            }
        }
        end
    } else {
        end
    };
    (start.saturating_add(column) <= content_end).then_some(start + column)
}

fn javascript_source_lines(source: &str) -> Vec<&str> {
    javascript_source_lines_with_offsets(source)
        .into_iter()
        .map(|(_, line)| line)
        .collect()
}

fn javascript_source_lines_with_offsets(source: &str) -> Vec<(usize, &str)> {
    let mut lines = Vec::new();
    let mut line_start = 0_usize;
    let mut characters = source.char_indices().peekable();
    while let Some((index, character)) = characters.next() {
        match character {
            '\r' => {
                lines.push((line_start, &source[line_start..index]));
                if characters
                    .peek()
                    .is_some_and(|(_, next_character)| *next_character == '\n')
                {
                    let (next_index, next_character) = characters.next().unwrap();
                    line_start = next_index + next_character.len_utf8();
                } else {
                    line_start = index + character.len_utf8();
                }
            }
            '\n' | '\u{2028}' | '\u{2029}' => {
                lines.push((line_start, &source[line_start..index]));
                line_start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    lines.push((line_start, &source[line_start..]));
    lines
}

fn bounded_match_context(
    line: &str,
    match_start: usize,
    match_end: usize,
    context_utf16: usize,
) -> String {
    let mut start = match_start;
    let mut remaining = context_utf16;
    for (index, character) in line[..match_start].char_indices().rev() {
        let width = character.len_utf16();
        if width > remaining {
            break;
        }
        remaining -= width;
        start = index;
    }
    let mut end = match_end;
    let mut remaining = context_utf16;
    for (offset, character) in line[match_end..].char_indices() {
        let width = character.len_utf16();
        if width > remaining {
            break;
        }
        remaining -= width;
        end = match_end + offset + character.len_utf8();
    }
    line[start..end].to_string()
}

fn one_based_location(location: &Value) -> Value {
    json!({
        "scriptId": location.get("scriptId"),
        "line": location
            .get("lineNumber")
            .and_then(Value::as_u64)
            .map(|line| line.saturating_add(1)),
        "column": location
            .get("columnNumber")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(1),
    })
}

fn same_cdp_location(left: &Value, right: &Value) -> bool {
    left.get("scriptId") == right.get("scriptId")
        && left.get("lineNumber") == right.get("lineNumber")
        && left
            .get("columnNumber")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            == right
                .get("columnNumber")
                .and_then(Value::as_u64)
                .unwrap_or(0)
}

async fn validate_expression_syntax(
    client: &CdpClient,
    session_id: &str,
    execution_context_id: Option<u64>,
    expression: &str,
    label: &str,
) -> Result<(), String> {
    let mut params = json!({
        "expression": format!("void ({})", expression),
        "sourceURL": format!("agent-browser-{}.js", label.replace(' ', "-")),
        "persistScript": false,
    });
    if let Some(context_id) = execution_context_id {
        params["executionContextId"] = json!(context_id);
    }
    let result = client
        .send_command("Runtime.compileScript", Some(params), Some(session_id))
        .await?;
    if let Some(details) = result.get("exceptionDetails") {
        let description = details
            .get("exception")
            .and_then(|exception| exception.get("description"))
            .and_then(Value::as_str)
            .or_else(|| details.get("text").and_then(Value::as_str))
            .unwrap_or("syntax error");
        return Err(format!("Invalid {}: {}", label, description));
    }
    Ok(())
}

fn build_logpoint_condition(
    binding_name: &str,
    nonce: &str,
    probe_id: &str,
    physical_id: &str,
    when: Option<&str>,
    expressions: &[String],
) -> Result<String, String> {
    let binding_name = serde_json::to_string(binding_name).map_err(|error| error.to_string())?;
    let nonce = serde_json::to_string(nonce).map_err(|error| error.to_string())?;
    let probe_id = serde_json::to_string(probe_id).map_err(|error| error.to_string())?;
    let physical_id = serde_json::to_string(physical_id).map_err(|error| error.to_string())?;
    let mut values = Vec::new();
    for expression in expressions {
        let label = serde_json::to_string(expression).map_err(|error| error.to_string())?;
        values.push(format!(
            "(()=>{{try{{return{{expression:{},value:__abSer(({}),0)}}}}catch(__abErr){{return{{expression:{},evaluationError:__abError(__abErr)}}}}}})()",
            label, expression, label
        ));
    }
    let when_expression = when
        .map(|expression| format!("Boolean(({}))", expression))
        .unwrap_or_else(|| "true".to_string());

    let mut condition = String::from(
        r#"(()=>{try{
let __abRemainingProperties=128;
const __abSeen=new WeakSet();
const __abError=(e)=>{try{return String(e&&e.message||e).slice(0,4096)}catch(_){return 'unprintable error'}};
const __abSer=(v,d)=>{try{
if(v===null||v===undefined||typeof v==='boolean')return v;
if(typeof v==='string')return v.length>4096?{type:'string',value:v.slice(0,4096),truncated:true}:v;
if(typeof v==='number')return Number.isFinite(v)?v:{type:'number',value:String(v)};
if(typeof v==='bigint')return{type:'bigint',value:String(v)};
if(typeof v==='symbol')return{type:'symbol',value:__abError(v)};
if(typeof v==='function')return{type:'function',name:(()=>{try{return String(v.name||'').slice(0,256)}catch(_){return''}})()};
if(typeof v!=='object')return{type:typeof v,value:__abError(v)};
if(__abSeen.has(v))return{type:'circular'};
if(d>=4)return{type:'truncated',reason:'max-depth'};
__abSeen.add(v);
if(Array.isArray(v)){
const a=[];let length=0;try{length=Math.min(Number(v.length)||0,64)}catch(e){return{type:'proxy-error',serializationError:__abError(e)}}
for(let i=0;i<length&&__abRemainingProperties>0;i++){__abRemainingProperties--;try{const descriptor=Object.getOwnPropertyDescriptor(v,String(i));if(descriptor&&Object.prototype.hasOwnProperty.call(descriptor,'value'))a.push(__abSer(descriptor.value,d+1));else if(descriptor)a.push({type:'accessor',read:false});else a.push({type:'missing'})}catch(e){a.push({type:'access-error',serializationError:__abError(e)})}}
if(length>=64)a.push({type:'truncated',reason:'max-array-length'});
if(__abRemainingProperties<=0)a.push({type:'truncated',reason:'max-properties'});
return a
}
const o={};let keys;try{keys=Reflect.ownKeys(v).slice(0,32)}catch(e){return{type:'proxy-error',serializationError:__abError(e)}}
for(const key of keys){if(__abRemainingProperties<=0){o.__truncated__={type:'truncated',reason:'max-properties'};break}__abRemainingProperties--;let name;try{name=String(key).slice(0,256)}catch(_){name='[unprintable-key]'}try{const descriptor=Object.getOwnPropertyDescriptor(v,key);if(descriptor&&Object.prototype.hasOwnProperty.call(descriptor,'value'))o[name]=__abSer(descriptor.value,d+1);else if(descriptor)o[name]={type:'accessor',read:false};else o[name]={type:'missing'}}catch(e){o[name]={type:'access-error',serializationError:__abError(e)}}}
return o
}catch(e){return{type:'serialization-error',serializationError:__abError(e)}}};
const __abUtf8Bytes=(s)=>{let bytes=0;for(let i=0;i<s.length;i++){const code=s.charCodeAt(i);if(code<128)bytes++;else if(code<2048)bytes+=2;else if(code>=55296&&code<=56319&&i+1<s.length){const next=s.charCodeAt(i+1);if(next>=56320&&next<=57343){bytes+=4;i++}else bytes+=3}else bytes+=3}return bytes};
"#,
    );
    condition.push_str("let __abWhenError=null;let __abRun=false;try{__abRun=");
    condition.push_str(&when_expression);
    condition.push_str(
        "}catch(e){__abWhenError=__abError(e)};if(!__abRun&&__abWhenError===null)return false;",
    );
    condition.push_str("const __abPayload={nonce:");
    condition.push_str(&nonce);
    condition.push_str(",probeId:");
    condition.push_str(&probe_id);
    condition.push_str(",physicalBindingId:");
    condition.push_str(&physical_id);
    condition.push_str(",values:__abRun?[");
    condition.push_str(&values.join(","));
    condition.push_str("]:[]};if(__abWhenError!==null)__abPayload.whenError=__abWhenError;");
    condition.push_str("let __abRaw=JSON.stringify(__abPayload);if(__abUtf8Bytes(__abRaw)>65536)__abRaw=JSON.stringify({nonce:");
    condition.push_str(&nonce);
    condition.push_str(",probeId:");
    condition.push_str(&probe_id);
    condition.push_str(",physicalBindingId:");
    condition.push_str(&physical_id);
    condition.push_str(
        ",values:[],serializationError:'payload-too-large'});const __abBinding=globalThis[",
    );
    condition.push_str(&binding_name);
    condition.push_str(
        "];if(typeof __abBinding==='function')__abBinding(__abRaw)}catch(_){ }return false})()",
    );
    Ok(condition)
}

fn runtime_owner(params: &Value) -> Value {
    let aux = params.get("executionContextAuxData");
    let is_default = aux
        .and_then(|value| value.get("isDefault"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let frame_id = aux
        .and_then(|value| value.get("frameId"))
        .and_then(Value::as_str);
    let mut evidence = Vec::new();
    if is_default {
        evidence.push(json!({ "kind": "execution-context-default" }));
    }
    if let Some(frame_id) = frame_id {
        evidence.push(json!({ "kind": "frame-id", "value": frame_id }));
    }
    json!({
        "status": "unknown",
        "owner": "unknown",
        "kind": "unknown",
        "ownerId": null,
        "confidence": "low",
        "evidence": evidence,
        "candidates": [],
        "reason": "A default page execution context is shared by Host and Module Federation remotes; runtime ownership requires caller-supplied evidence",
    })
}

fn invalidate_session_probes_locked(
    state: &mut ControllerState,
    session_id: &str,
    document_generation: u64,
    reason: &str,
) {
    let physical_ids: Vec<String> = state
        .physical_probes
        .values()
        .filter(|binding| {
            binding.session_id == session_id
                && (document_generation == u64::MAX
                    || binding.document_generation == document_generation)
        })
        .map(|binding| binding.physical_id.clone())
        .collect();
    for physical_id in physical_ids {
        if let Some(binding) = state.physical_probes.remove(&physical_id) {
            state
                .physical_by_cdp_breakpoint
                .remove(&binding.cdp_breakpoint_id);
            let mut status = reason.to_string();
            if let Some(probe) = state.logical_probes.get_mut(&binding.probe_id) {
                probe.physical_ids.retain(|id| id != &physical_id);
                status = if probe.persistent {
                    format!("{}-awaiting-rebind", reason)
                } else {
                    reason.to_string()
                };
                probe.status = status.clone();
            }
            push_event_locked(
                state,
                "probe-unbound",
                Some(session_id),
                json!({
                    "probeId": binding.probe_id,
                    "physicalBindingId": binding.physical_id,
                    "reason": reason,
                    "status": status,
                }),
            );
        }
    }
}

fn invalidate_context_probes_locked(
    state: &mut ControllerState,
    session_id: &str,
    execution_context_id: u64,
    reason: &str,
) {
    let physical_ids: Vec<String> = state
        .physical_probes
        .values()
        .filter(|binding| {
            binding.session_id == session_id
                && binding.execution_context_id == Some(execution_context_id)
        })
        .map(|binding| binding.physical_id.clone())
        .collect();
    for physical_id in physical_ids {
        if let Some(binding) = state.physical_probes.remove(&physical_id) {
            state
                .physical_by_cdp_breakpoint
                .remove(&binding.cdp_breakpoint_id);
            let mut status = reason.to_string();
            if let Some(probe) = state.logical_probes.get_mut(&binding.probe_id) {
                probe.physical_ids.retain(|id| id != &physical_id);
                status = if probe.persistent {
                    format!("{}-awaiting-rebind", reason)
                } else {
                    reason.to_string()
                };
                probe.status = status.clone();
            }
            push_event_locked(
                state,
                "probe-unbound",
                Some(session_id),
                json!({
                    "probeId": binding.probe_id,
                    "physicalBindingId": binding.physical_id,
                    "executionContextId": execution_context_id,
                    "reason": reason,
                    "status": status,
                }),
            );
        }
    }
}

fn mark_all_probes_stale_locked(state: &mut ControllerState, reason: &str) {
    let stale: Vec<(String, Vec<String>)> = state
        .logical_probes
        .values()
        .map(|probe| (probe.probe_id.clone(), probe.physical_ids.clone()))
        .collect();
    for (probe_id, physical_ids) in stale {
        if let Some(probe) = state.logical_probes.get_mut(&probe_id) {
            probe.physical_ids.clear();
            probe.status = "stale".to_string();
        }
        for physical_id in physical_ids {
            push_event_locked(
                state,
                "probe-unbound",
                None,
                json!({
                    "probeId": probe_id,
                    "physicalBindingId": physical_id,
                    "reason": reason,
                    "status": "stale",
                }),
            );
        }
    }
}

fn one_based(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).map(|n| n.saturating_add(1))
}

fn resolve_session_id(state: &ControllerState, cmd: &Value) -> Result<String, String> {
    if cmd.get("sessionId").is_some() && cmd.get("tabId").is_some() {
        return Err("Use either a tab ID or a CDP session ID, not both".to_string());
    }
    if let Some(session_id) = cmd.get("sessionId").and_then(Value::as_str) {
        if state.sessions.contains_key(session_id) {
            return Ok(session_id.to_string());
        }
        return Err(format!("Unknown CDP session '{}'", session_id));
    }
    if let Some(tab_id) = cmd.get("tabId").and_then(Value::as_str) {
        return state
            .sessions
            .values()
            .find(|session| session.tab_id == tab_id)
            .map(|session| session.session_id.clone())
            .ok_or_else(|| format!("Unknown tab '{}'", tab_id));
    }
    state
        .active_session
        .clone()
        .ok_or_else(|| "No active CDP session".to_string())
}

fn resolve_pause<'a>(state: &'a ControllerState, cmd: &Value) -> Result<&'a PauseRecord, String> {
    let session_selectors = usize::from(cmd.get("pauseId").is_some())
        + usize::from(cmd.get("sessionId").is_some())
        + usize::from(cmd.get("tabId").is_some());
    if session_selectors > 1 {
        return Err("Use exactly one of pause ID, tab ID, or CDP session ID".to_string());
    }
    if let Some(pause_id) = cmd.get("pauseId").and_then(Value::as_str) {
        return state
            .paused_sessions
            .values()
            .find(|pause| pause.pause_id == pause_id)
            .ok_or_else(|| format!("Unknown or stale pause ID '{}'", pause_id));
    }
    if let Some(session_id) = cmd.get("sessionId").and_then(Value::as_str) {
        return state
            .paused_sessions
            .get(session_id)
            .ok_or_else(|| format!("Session '{}' is not paused", session_id));
    }
    if let Some(tab_id) = cmd.get("tabId").and_then(Value::as_str) {
        return state
            .paused_sessions
            .values()
            .find(|pause| pause.tab_id == tab_id)
            .ok_or_else(|| format!("Tab '{}' is not paused", tab_id));
    }
    match state.paused_sessions.len() {
        0 => Err("No JavaScript session is paused".to_string()),
        1 => Ok(state.paused_sessions.values().next().unwrap()),
        count => Err(format!(
            "{} JavaScript sessions are paused; specify --tab, --session, or --pause-id",
            count
        )),
    }
}

fn push_event_locked(
    state: &mut ControllerState,
    event_type: &str,
    session_id: Option<&str>,
    data: Value,
) {
    state.latest_sequence = state.latest_sequence.saturating_add(1);
    let sequence = state.latest_sequence;
    let session = session_id.and_then(|id| state.sessions.get(id));
    let event = json!({
        "sequence": sequence,
        "timestamp": timestamp_ms(),
        "type": event_type,
        "connectionGeneration": state.connection_generation,
        "tabId": session.map(|s| s.tab_id.clone()),
        "targetId": session.map(|s| s.target_id.clone()),
        "sessionId": session_id,
        "documentGeneration": session.map(|s| s.document_generation),
        "data": data,
    });
    state.events.push_back(event);
    state.event_bytes = state.event_bytes.saturating_add(
        state
            .events
            .back()
            .map(|event| event.to_string().len())
            .unwrap_or(0),
    );
    while state.events.len() > MAX_DEBUG_EVENTS || state.event_bytes > MAX_DEBUG_EVENT_BYTES {
        if let Some(removed) = state.events.pop_front() {
            state.event_bytes = state.event_bytes.saturating_sub(removed.to_string().len());
            state.dropped_through_sequence = removed.get("sequence").and_then(Value::as_u64);
        } else {
            break;
        }
    }
}

fn timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

enum FastPolicyDecision {
    Allow,
    Deny(String),
    Confirm(String),
}

fn check_fast_policy(cmd: &Value) -> FastPolicyDecision {
    let categories = fast_policy_categories(cmd);
    let mut confirmations = Vec::new();
    if let Some(policy) = ActionPolicy::load_if_exists() {
        for category in &categories {
            match policy.check(category) {
                PolicyResult::Allow => {}
                PolicyResult::Deny(reason) => return FastPolicyDecision::Deny(reason),
                PolicyResult::RequiresConfirmation => {
                    confirmations.push((*category).to_string());
                }
            }
        }
    }
    if let Some(actions) = ConfirmActions::from_env() {
        for category in &categories {
            if actions.requires_confirmation(category)
                && !confirmations.iter().any(|pending| pending == category)
            {
                confirmations.push((*category).to_string());
            }
        }
    }
    if !confirmations.is_empty() {
        return FastPolicyDecision::Confirm(confirmations.join(","));
    }
    FastPolicyDecision::Allow
}

fn fast_policy_categories(cmd: &Value) -> Vec<&str> {
    let action = cmd.get("action").and_then(Value::as_str).unwrap_or("");
    let primary_category = match action {
        "debug_eval" => "evaluate",
        "debug_resume" | "debug_pause" | "debug_step_over" | "debug_step_into"
        | "debug_step_out" | "debug_disable" => "debug.control",
        "debug_enable" => "debug.control",
        "debug_scripts"
        | "debug_source"
        | "debug_source_search"
        | "debug_stack"
        | "debug_status"
        | "debug_events"
        | "debug_breakpoint_list"
        | "debug_logpoint_list" => "debug.inspect",
        "debug_breakpoint_set"
        | "debug_breakpoint_remove"
        | "debug_logpoint_set"
        | "debug_logpoint_remove" => "debug.control",
        _ => action,
    };
    let mut categories = vec![primary_category];
    let evaluates_page_code = action == "debug_logpoint_set"
        || (action == "debug_breakpoint_set"
            && cmd
                .get("condition")
                .and_then(Value::as_str)
                .is_some_and(|condition| !condition.trim().is_empty()));
    if evaluates_page_code && !categories.contains(&"evaluate") {
        categories.push("evaluate");
    }
    categories
}

fn validate_fast_selectors(cmd: &Value) -> Result<(), String> {
    let has_tab = cmd.get("tabId").is_some();
    let has_session = cmd.get("sessionId").is_some();
    let has_pause = cmd.get("pauseId").is_some();
    let all_tabs = cmd.get("allTabs").and_then(Value::as_bool).unwrap_or(false);
    if has_tab && has_session {
        return Err("Use either a tab ID or a CDP session ID, not both".to_string());
    }
    if has_pause && (has_tab || has_session) {
        return Err("A pause ID cannot be combined with a tab or session selector".to_string());
    }
    if all_tabs && (has_tab || has_session || has_pause) {
        return Err("allTabs cannot be combined with a page or pause selector".to_string());
    }
    if cmd.get("frame").is_some() && cmd.get("callFrameId").is_some() {
        return Err("Use either a frame index or call frame ID, not both".to_string());
    }
    Ok(())
}

fn success_response(id: &str, data: Value) -> Value {
    json!({ "id": id, "success": true, "data": data })
}

fn error_response(id: &str, error: &str) -> Value {
    json!({ "id": id, "success": false, "error": error })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiple_pauses_require_an_explicit_selector() {
        let mut state = ControllerState::default();
        for (index, session_id) in ["s1", "s2"].iter().enumerate() {
            state.paused_sessions.insert(
                session_id.to_string(),
                PauseRecord {
                    pause_id: format!("pause-1-{}", index + 1),
                    connection_generation: 1,
                    tab_id: format!("t{}", index + 1),
                    session_id: session_id.to_string(),
                    document_generation: 1,
                    reason: "other".to_string(),
                    hit_breakpoints: Vec::new(),
                    probe_ids: Vec::new(),
                    call_frames: Vec::new(),
                    data: None,
                },
            );
        }
        let error = resolve_pause(&state, &json!({})).unwrap_err();
        assert!(error.contains("specify --tab, --session, or --pause-id"));
        assert_eq!(
            resolve_pause(&state, &json!({ "tabId": "t2" }))
                .unwrap()
                .session_id,
            "s2"
        );
    }

    #[test]
    fn event_ring_reports_evicted_sequence() {
        let mut state = ControllerState::default();
        for _ in 0..=MAX_DEBUG_EVENTS {
            push_event_locked(&mut state, "test", None, json!({}));
        }
        assert_eq!(state.events.len(), MAX_DEBUG_EVENTS);
        assert_eq!(state.dropped_through_sequence, Some(1));
    }

    #[test]
    fn transport_gap_records_a_distinct_cursor() {
        let controller = DebuggerController::new();
        controller.state.write().unwrap().connection_generation = 7;
        controller.record_transport_gap(7, 3);
        let state = controller.state.read().unwrap();
        assert_eq!(state.last_transport_gap_sequence, Some(1));
        assert_eq!(state.events[0]["type"], "transport-gap");
        assert_eq!(state.events[0]["data"]["droppedEventCount"], 3);
    }

    #[test]
    fn breakpoint_location_selection_is_bounded_and_one_based() {
        let source = "let a = 1;\nlet emoji = '😀';\nfinish();";
        let locations = vec![
            json!({ "scriptId": "7", "lineNumber": 9, "columnNumber": 4 }),
            json!({ "scriptId": "7", "lineNumber": 0, "columnNumber": 4 }),
            json!({ "scriptId": "7", "lineNumber": 1, "columnNumber": 4 }),
            json!({ "scriptId": "7", "lineNumber": 2, "columnNumber": 0 }),
        ];
        let request =
            |line, column, column_explicit, mode, max_utf16_distance| BreakpointResolutionRequest {
                line,
                column,
                column_explicit,
                mode,
                max_lines: 3,
                max_utf16_distance,
            };
        let (strict, reason, distance) =
            select_breakpoint_location(&locations, request(1, 5, true, "strict", 512), source)
                .unwrap();
        assert_eq!(strict["lineNumber"], 0);
        assert_eq!(reason, "exact");
        assert_eq!(distance, 0);

        assert!(
            select_breakpoint_location(&locations, request(1, 6, true, "strict", 512), source)
                .is_err()
        );
        let (line_strict, reason, _) =
            select_breakpoint_location(&locations, request(2, 1, false, "strict", 512), source)
                .unwrap();
        assert_eq!(line_strict["lineNumber"], 1);
        assert_eq!(reason, "first-breakable-on-requested-line");
        let (after, _, _) =
            select_breakpoint_location(&locations, request(1, 6, true, "after", 512), source)
                .unwrap();
        assert_eq!(after["lineNumber"], 1);
        let (before, _, _) =
            select_breakpoint_location(&locations, request(2, 6, true, "before", 512), source)
                .unwrap();
        assert_eq!(before["lineNumber"], 1);
        assert!(
            select_breakpoint_location(&locations, request(1, 6, true, "after", 1), source)
                .is_err()
        );
    }

    #[test]
    fn logpoint_condition_uses_binding_and_bounded_serializer() {
        let condition = build_logpoint_condition(
            "__agent_browser_debug_hit_random",
            "nonce",
            "probe-1",
            "physical-1",
            Some("state.ready"),
            &["state".to_string(), "total".to_string()],
        )
        .unwrap();
        assert!(condition.contains("__agent_browser_debug_hit_random"));
        assert!(condition.contains("state.ready"));
        assert!(condition.contains("max-properties"));
        assert!(condition.contains("payload-too-large"));
        assert!(condition.contains("Object.getOwnPropertyDescriptor"));
        assert!(!condition.contains("console.log"));
        assert!(condition.ends_with("()"));
    }

    #[test]
    fn runtime_owner_does_not_infer_host_from_default_context() {
        let owner = runtime_owner(&json!({
            "executionContextAuxData": { "isDefault": true, "frameId": "frame-1" }
        }));
        assert_eq!(owner["status"], "unknown");
        assert!(owner["ownerId"].is_null());
        assert!(owner["evidence"]
            .as_array()
            .unwrap()
            .contains(&json!({ "kind": "execution-context-default" })));
        assert!(owner["evidence"]
            .as_array()
            .unwrap()
            .contains(&json!({ "kind": "frame-id", "value": "frame-1" })));

        let unknown = runtime_owner(&json!({
            "executionContextAuxData": { "isDefault": false, "frameId": "frame-1" }
        }));
        assert_eq!(unknown["status"], "unknown");
        assert!(unknown["ownerId"].is_null());
    }

    #[test]
    fn javascript_lines_and_utf16_offsets_use_ecmascript_line_terminators() {
        let source = "a\r\nb😀\u{2028}c\u{2029}";
        assert_eq!(javascript_source_lines(source), vec!["a", "b😀", "c", ""]);
        assert_eq!(utf16_offset_for_location(source, 1, 3), Some(6));
        assert_eq!(utf16_offset_for_location(source, 1, 4), None);

        let line = "😀abMATCHcd😀";
        let start = line.find("MATCH").unwrap();
        assert_eq!(
            bounded_match_context(line, start, start + "MATCH".len(), 2),
            "abMATCHcd"
        );
    }

    #[test]
    fn logpoints_and_conditional_breakpoints_require_evaluate_policy() {
        assert_eq!(
            fast_policy_categories(&json!({ "action": "debug_logpoint_set" })),
            vec!["debug.control", "evaluate"]
        );
        assert_eq!(
            fast_policy_categories(&json!({
                "action": "debug_breakpoint_set",
                "condition": "ready"
            })),
            vec!["debug.control", "evaluate"]
        );
        assert_eq!(
            fast_policy_categories(&json!({ "action": "debug_breakpoint_set" })),
            vec!["debug.control"]
        );
    }
}
