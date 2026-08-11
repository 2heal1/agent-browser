# Compiled JavaScript debugging

Use this workflow to debug JavaScript exactly as Chrome loaded it. Project sources and source maps are optional and are not consulted by these commands.

## Start and discover scripts

```bash
agent-browser open https://app.example.com
agent-browser debug enable
agent-browser debug scripts --filter assets --json
agent-browser debug source search "checkout" --filter assets --json
agent-browser debug source <script-id>
```

`debug enable` enables `Runtime`, `Debugger`, and `Page` for the active tab. Pass `--all-tabs` to enable every current top-level page, or select one with `--tab <tN>` or `--session <cdp-session-id>`.

`debug source <script-id>` returns at most 32 MiB in one response. `debug source search` returns one-based UTF-16 start and end coordinates, byte offsets, and at most 160 UTF-16 code units of context on each side. Search returns 100 matches by default and accepts an explicit maximum up to 1,000.

`debug scripts` records each `Debugger.scriptParsed` event. Script records include URL, hash, execution context, compiled extent, runtime owner evidence, and two different identities:

- `scriptInstanceKey` is `connectionGeneration + sessionId + documentGeneration + scriptId`. Use it for exact CDP operations.
- `sourceLineageKey` is `sessionId + documentGeneration + executionContextId + URL or sourceURL + resolvedRuntimeOwnerId`. Use it only when deciding whether a logical probe may rebind to a new script instance.

The initiating or parent script is evidence, never an identity component. Runtime ownership is reported with `status`, `kind`, `ownerId`, `confidence`, `evidence`, and `candidates`. A default page execution context can contain both Host and Module Federation remote code, so the generic substrate reports it as `unknown`. Reliable owner resolution belongs in the Divebell extension. `unknown` and `ambiguous` owners never auto-rebind.

## Locations

CLI locations are one-based. Columns count UTF-16 code units so non-ASCII compiled text maps to Chrome correctly.

Before setting a probe, agent-browser calls `Debugger.getPossibleBreakpoints` with `restrictToFunction: true`.

- `--strict` accepts a breakable location on the requested line. When `--column` is supplied, the column must also match.
- `--before` selects the closest earlier location only after Chrome proves that it reaches an anchor in the requested function.
- `--after` selects the closest location at or after the request in the same function. This is the default.
- `--nearest` compares verified backward candidates with forward candidates and prefers forward when distances tie.
- `--nearest-forward` is a compatibility alias for `--after`.
- `--max-lines <n>` changes the default three-line bound, up to 500.
- `--max-utf16-distance <n>` changes the default 512 UTF-16 code unit bound, up to 1,000,000.

If no bounded location is found, the command fails without installing a breakpoint.

## Breakpoints

```bash
agent-browser debug breakpoint set <script-id> <line> --strict --json
agent-browser debug breakpoint set <script-id> <line> --condition "order.total > 100" --json
agent-browser debug breakpoint list --json
agent-browser debug breakpoint remove <probe-id>
```

Conditions are syntax checked with `Runtime.compileScript` in the script's execution context before the physical breakpoint is installed. Syntax success does not prove that runtime scope variables exist. Scope failures are returned as evaluation evidence and must not be converted into an unrelated debugger pause.

A logical probe has a stable `probeId`. Each compiled script installation creates a separate physical record containing `physicalId`, CDP breakpoint ID, session, document generation, script ID, execution context, requested location, and actual location.

## Pause recovery

A normal daemon command holds ordinary browser state while it waits for a renderer response. A renderer stopped at a breakpoint cannot finish that command. Debugger inspection and control therefore use an independent controller, event receiver, state lock, and direct CDP command path.

One shell can trigger a pause:

```bash
agent-browser eval "startCheckout()"
```

A second shell or MCP request can recover it:

```bash
agent-browser debug status --json
agent-browser debug stack --json
agent-browser debug eval "order.id" --frame 0 --json
agent-browser debug step-over
agent-browser debug resume
```

Each pause receives a generation-scoped `pauseId`. If exactly one session is paused, the selector can be omitted. If more than one session is paused, use exactly one of:

```bash
--tab <tN>
--session <cdp-session-id>
--pause-id <pause-id>
```

`debug eval` accepts either `--frame <zero-based-index>` or `--call-frame-id <id>`. An explicit call frame ID must belong to the selected pause.

Ordinary renderer commands fail early when the active tab is already paused. Tab management remains available. A tab switch reports `debuggerPaused: true` rather than treating the paused renderer as a discarded tab and attempting recovery that could alter state.

## Logpoints

Logpoints collect evidence without pausing:

```bash
agent-browser debug logpoint set <script-id> <line> \
  --when "order.ready" \
  --expression "order" \
  --expression "cart.total" \
  --tag phase=checkout \
  --json

agent-browser debug events --since 0 --wait 5000 --json
```

The physical breakpoint condition always returns false. When `--when` is false it emits nothing. Otherwise it serializes each expression independently, then calls a random per-connection private Runtime binding. The browser console is not an authoritative delivery channel.

Serialization has fixed limits for depth, properties, array items, strings, and a 64 KiB total payload. It does not invoke accessors through ordinary property reads. Cycles, `BigInt`, non-finite numbers, functions, symbols, accessors, throwing getters, proxy traps, and expression failures receive explicit representations rather than escaping the condition or pausing the page. A thrown `--when` expression is reported as `whenError`; a thrown value expression is reported as `evaluationError`.

Every binding message is validated against:

- connection nonce
- CDP session
- execution context when known
- logical probe ID
- active physical binding ID
- enabled logpoint registry state

The payload supplies only serialized expression values and the validation IDs. Script identity, compiled location, runtime owner, and tags come from the daemon registry. Rejected payloads create a `logpoint-rejected` event.

Removing the final logpoint for a session calls `Runtime.removeBinding`. Disabling the debugger removes the binding and all Debugger-domain state.

## Events and gaps

```bash
agent-browser debug events --since <sequence> --wait <milliseconds> --json
agent-browser debug events --clear --json
```

The debugger keeps events independently of individual CLI connections. The ring is capped at 10,000 events and 8 MiB. Every response includes:

- `oldestSequence`
- `latestSequence`
- `gap`
- `bufferGap`
- `transportGap`
- `droppedThroughSequence`
- `lastTransportGapSequence`

`bufferGap: true` means the requested cursor is older than retained history. `transportGap: true` and a `transport-gap` event mean the controller's CDP broadcast receiver lagged after that cursor and browser events may have been lost. `gap` is true for either condition. Treat a gap as incomplete evidence and refresh debugger status, scripts, and probes before making automated conclusions.

Relevant event types include `target-attached`, `target-detached`, `script-parsed`, `probe-bound`, `probe-unbound`, `probe-rebind-failed`, `probe-removed`, `debugger-paused`, `debugger-resumed`, `logpoint-hit`, `logpoint-rejected`, `document-invalidated`, `document-committed`, `execution-context-created`, `execution-context-destroyed`, `execution-contexts-cleared`, `session-detached`, `connection-reset`, `binding-residue`, and `transport-gap`.

## Lifecycle and rebinding

Navigation, target detach, browser close, and connection replacement invalidate physical bindings and pauses. Connection generation and document generation prevent stale IDs from being reused.

`--persist` allows same-document rebinding when HMR creates a new script instance. Rebinding requires all of the following:

- same browser connection generation
- same CDP session
- same document generation
- same execution context
- same compiled URL or sourceURL
- same resolved runtime owner ID

Unknown or ambiguous ownership changes the probe status to `awaiting-owner-evidence` and performs no automatic action. Navigation never inherits a probe into the next document generation. Browser reconnect never inherits a probe into the next connection generation.

## Rstack HMR and Module Federation

Core agent-browser deliberately provides generic CDP facts rather than framework conclusions. The Divebell extension should consume the event stream and add framework-specific grouping.

For Rstack HMR, the extension should create a runtime-scoped cycle with a stable cycle ID, start and completion evidence, affected script instances, probe rebind attempts, and one of these outcomes: applied, failed, aborted, timed out, or incomplete because of an event gap. State preservation must be reported as `verified-preserved`, `verified-reset`, or `not-verified`; a successful HMR transport message is not proof that application state survived.

For Module Federation shared modules, aggregate by consumer, runtime instance, and share scope. Do not aggregate only by package name or resolved URL. A host and multiple remotes can load the same compiled URL under different ownership and sharing decisions. If owner resolution has multiple candidates, preserve all candidates and report `ambiguous`; do not silently select a parent or initiator.

## MCP mapping

Start the server with the debug profile:

```bash
agent-browser mcp --tools debug
```

The profile includes dedicated typed tools for debugger enable, disable, status, scripts, source read and search, breakpoint set/list/remove, logpoint set/list/remove, pause, resume, step over/into/out, stack, frame evaluation, and events. Tool implementations delegate through the canonical CLI parser. Advanced global CLI fields, including session isolation and confirmation policy, remain available through the common MCP arguments.

## Security

Debugger commands use the same action policy and confirmation sources as ordinary commands. Inspection maps to `debug.inspect`, frame evaluation maps to `evaluate`, and mutation or execution control maps to `debug.control`. Logpoints and conditional breakpoints require both `debug.control` and `evaluate` because their expressions run in page context. Policy denial takes precedence over confirmation when multiple categories apply. Confirmation for debugger recovery is itself lock-independent, so a required approval does not make a paused page impossible to resume.

Frame evaluation and logpoint expressions execute in page context and can have side effects. Treat them as code execution. Logpoint events can contain application data or credentials even with size limits. Keep event output within trusted agent and storage boundaries.

## Limitations

- Chrome and Chromium only
- Compiled locations only; no source map remapping
- Top-level page sessions are managed directly; framework worker attribution requires extension evidence
- Persistent rebinding is conservative by design
- HMR cycle semantics and Module Federation ownership are extension responsibilities
