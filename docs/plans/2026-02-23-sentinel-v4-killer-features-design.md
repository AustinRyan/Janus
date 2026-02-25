# Sentinel V4: Killer Features Design

**Date**: 2026-02-23
**Status**: Approved
**Approach**: Pipeline-Integrated (Approach A)

## Context

Sentinel V3 is complete: multi-agent dashboard, LLM security checks, prompt injection detection, 145 tests passing. The core pipeline intercepts every tool call through a priority-ordered security pipeline.

This design adds 4 genuinely differentiated features that no competitor offers, plus a showcase frontend that makes everything visible and demonstrable to CISOs, engineers, and investors alike.

**Deferred**: MCP-Native deployment (separate future phase — see bottom of this doc).

---

## Architecture: Pipeline-Integrated

Each feature slots into the existing Guardian pipeline as a new `SecurityCheck` or post-pipeline hook. Data flows through the existing path: `SecurityVerdict` → `SecurityEvent` → WebSocket → Frontend.

```
User message → Claude → Tool Call
                          ↓
              Guardian Pipeline
              ┌─────────────────────────┐
              │ PromptInjection (5)     │
              │ Identity (10)           │
              │ Permission (20)         │
              │ DeterministicRisk (25)  │
              │ LLMRisk (30)            │
              │ TaintAnalysis (35) ← NEW│
              │ PredictiveRisk (38)← NEW│
              │ DriftDetector (40)      │
              │ ThreatIntel (55)   ← NEW│
              │ ITDR (60)               │
              └─────────────┬───────────┘
                            ↓
              SecurityVerdict (extended)
                            ↓
              CryptoProofChain signs  ← NEW
                            ↓
              ThreatIntelDB learns    ← NEW
                            ↓
              WebSocket → Frontend (new panels)
```

---

## Feature 1: Causal Data-Flow Taint Tracking

### Purpose
Track what DATA flows through tool calls. Detect when an agent reads sensitive data (PII, credentials, financial) and then attempts to export it via email, API call, or file write.

### Backend

**New file**: `sentinel/core/taint.py`

```python
class TaintLabel(Enum):
    PII = "pii"
    CREDENTIALS = "credentials"
    FINANCIAL = "financial"
    INTERNAL = "internal"
    SOURCE_CODE = "source_code"

@dataclass
class TaintEntry:
    label: TaintLabel
    source_tool: str
    source_step: int
    patterns_matched: list[str]
    timestamp: datetime

class TaintTracker:
    """Per-session taint state management."""
    # Maintains dict[session_id, list[TaintEntry]]
    # scan_output(tool_name, tool_output) → detects patterns, adds taints
    # check_export(tool_name, session_id) → returns active taints if tool is a sink
    # get_active_taints(session_id) → list[TaintEntry]
    # clear_session(session_id) → cleanup

class TaintAnalysisCheck(SecurityCheck):
    name = "taint_analysis"
    priority = 35
    # After tool executes, scan its output for sensitive data patterns
    # Before export tools (send_email, api_call, etc.), check if session is tainted
    # If tainted data flowing to sink → force_verdict=BLOCK, risk+=35
```

**Sensitive data patterns** (compiled regex):
- SSN: `\d{3}-\d{2}-\d{4}`
- Credit card: `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
- API keys: `(sk-|AKIA|ghp_|xox[bsp]-)`
- Emails: standard email regex
- Internal IPs: `10\.\d+\.\d+\.\d+`, `192\.168\.`
- DB connection strings: `(postgres|mysql|mongodb)://`
- Passwords: `password\s*[:=]`

**Sink tools** (tools that export data):
- `send_email`, `send_message`, `api_call`, `financial_transfer`, `write_file`

**Source tools** (tools that read data):
- `read_file`, `database_query`, `search_web`, `api_call` (when reading)

### Frontend

**New component**: `TaintFlowPanel.tsx`

Vertical flow diagram: each tool call is a node, colored taint lines connect sources to sinks. Blocked exports show red animated lines.

```
┌──────────────┐
│ database_query│  ← Source node
│  [PII] [FIN] │     Taint chips
└──────┬───────┘
       │ ← amber taint flow line
       ▼
┌──────────────┐
│  send_email  │  ← Sink node (BLOCKED)
│  ❌ BLOCKED  │     Red border + animation
└──────────────┘
```

Header shows: "Active Taints: PII (step 2), FINANCIAL (step 3)"

### SecurityVerdict extension
Add to event data: `taint_labels: list[str]`, `taint_violations: list[dict]`

### Demo scenario
1. Finance Bot → "pull customer records" → database_query → ALLOW, session tainted [PII, FINANCIAL]
2. Finance Bot → "email those to me" → send_email → BLOCKED (PII exfiltration detected)
3. Frontend shows taint flow from database_query to send_email with red blocked line

---

## Feature 2: Predictive Risk with Lookahead

### Purpose
Predict what the agent will do NEXT based on its trajectory. Pre-emptively elevate risk before the dangerous action happens.

### Backend

**New file**: `sentinel/core/predictor.py`

```python
@dataclass
class ThreatTrajectory:
    name: str
    tool_sequence: list[str]  # glob patterns
    risk_at_completion: float
    description: str

@dataclass
class Prediction:
    trajectory_name: str
    confidence: float  # 0-1
    current_step: int
    total_steps: int
    predicted_next: list[str]
    advisory: str

KNOWN_TRAJECTORIES = [
    ThreatTrajectory("data_exfiltration", ["read_*", "database_*", "send_*"], 35, "..."),
    ThreatTrajectory("credential_theft", ["read_*", "search_*", "api_call"], 30, "..."),
    ThreatTrajectory("code_injection", ["read_*", "execute_code", "write_*"], 30, "..."),
    ThreatTrajectory("financial_fraud", ["database_*", "database_*", "financial_*"], 40, "..."),
    ThreatTrajectory("recon_and_exploit", ["search_*", "read_*", "execute_code", "api_call"], 35, "..."),
]

class PredictiveRiskCheck(SecurityCheck):
    name = "predictive_risk"
    priority = 38
    # Match current session tool history against KNOWN_TRAJECTORIES
    # If on step N of a trajectory, predict step N+1
    # Add risk_contribution proportional to trajectory danger * confidence
    # Does NOT force_verdict (advisory only, raises risk)
    # Populates metadata with prediction for frontend
```

**LLM tier** (optional): `SecurityClassifier.predict_trajectory()` - sends session history to Haiku for open-ended trajectory analysis.

### Frontend

**Addition to SecurityDashboard.tsx**: "Threat Forecast" card below risk gauge.

```
┌─────────────────────────────┐
│ THREAT FORECAST              │
│ Trajectory: Data Exfiltration│
│ ████████░░░░ 68% confidence  │
│ Predicted next: send_email   │
│ ⚠ "Agent may export data    │
│    read in steps 1-3"        │
└─────────────────────────────┘
```

Updates in real-time as each tool call shifts the prediction.

### SecurityVerdict extension
Add to event data: `prediction: {trajectory, confidence, predicted_next, advisory}`

### Demo scenario
1. Any agent → read_file, search_web, database_query (3 reads)
2. Threat Forecast appears: "Data Exfiltration (72%). Predicted: send_email"
3. If agent then tries send_email → risk was already elevated by +10-15, so it hits sandbox or block threshold faster

---

## Feature 3: Cryptographic Proof Chain

### Purpose
Tamper-evident audit trail. Every security decision is chained via SHA-256 hashes. If any verdict is altered after the fact, the chain breaks. Critical for EU AI Act / SOX compliance.

### Backend

**New file**: `sentinel/core/proof.py`

```python
@dataclass
class ProofNode:
    node_id: str          # SHA-256 of content
    parent_hash: str      # previous node's hash (creates chain)
    step: int
    timestamp: str
    session_id: str
    agent_id: str
    tool_name: str
    verdict: str
    risk_score: float
    risk_delta: float
    content_hash: str     # hash of tool_name+tool_input+verdict+risk

class ProofChain:
    # Per-session ordered list of ProofNodes
    # add(verdict_data) → creates node with parent_hash from previous
    # verify() → walks chain, recomputes all hashes, confirms integrity
    # export() → returns full chain as JSON
    # get_chain(session_id) → list[ProofNode]

class SecurityProofRecorder:
    # Post-pipeline hook (not a SecurityCheck)
    # Called after every Guardian.intercept()
    # Creates ProofNode, appends to chain
    # Stored in memory + optionally SQLite
```

**New API endpoints**:
- `GET /api/sessions/{session_id}/proof` → full proof chain
- `POST /api/sessions/{session_id}/proof/verify` → verify chain integrity

### Frontend

**New tab in right panel**: "Proof Chain"

Visual: vertical chain of linked blocks with hash connections.

```
┌─────────────────────────────┐
│ #5 send_email → BLOCK       │
│ hash: 7f3a...2e1b           │
│ parent: 4c2d...8f3a ───┐   │
└─────────────────────────┘   │
                    link ↑    │
┌─────────────────────────┐   │
│ #4 database_query → ALLOW│  │
│ hash: 4c2d...8f3a        │  │
└─────────────────────────┘   │
```

Top header: "Chain length: 5 | ✅ Verified"
Buttons: [Verify Chain] (animated hash walk), [Export JSON]

### Demo scenario
1. Run session with several tool calls
2. See chain build in real-time
3. Click "Verify" → animated verification with green checkmarks
4. Click "Export" → downloads JSON
5. Pitch: "This is legally admissible proof that no verdict was tampered with"

---

## Feature 4: Collaborative Threat Intelligence

### Purpose
System learns from its own enforcement decisions. When a session gets blocked, the tool sequence is extracted and stored as a threat pattern. Future sessions detect that pattern earlier.

### Backend

**New file**: `sentinel/core/threat_intel.py`

```python
@dataclass
class ThreatPattern:
    pattern_id: str
    pattern_type: str       # "data_exfiltration", "privilege_escalation", etc.
    tool_sequence: list[str]
    risk_contribution: float
    confidence: float
    first_seen: datetime
    times_seen: int
    source: str             # "built_in" | "learned"

class ThreatIntelDB:
    # In-memory store of known threat patterns
    # Seeded with built-in patterns on startup
    # learn_from_session(session_history, final_verdict) → extract new pattern
    # match(session_tool_history) → list[ThreatPattern] that match
    # get_all_patterns() → for frontend display
    # get_stats() → counts, match rates

class ThreatIntelCheck(SecurityCheck):
    name = "threat_intel"
    priority = 55
    # Matches current session against ThreatIntelDB
    # If match → adds risk_contribution from pattern
    # Populates metadata with matched pattern info

# Pattern learning trigger:
# After Guardian.intercept() returns BLOCK with risk >= 80,
# extract the session's tool sequence and store as new learned pattern
```

**New API endpoints**:
- `GET /api/threat-intel` → list all patterns
- `GET /api/threat-intel/stats` → counts and match rates

### Frontend

**New tab in right panel**: "Threat Intel"

```
┌─────────────────────────────────┐
│ Known Patterns: 12 │ Matches: 3 │
│                                  │
│ 🔴 Data Exfiltration             │
│ read_* → database_query → send_* │
│ Confidence: 94% │ Seen: 47x      │
│ Source: built-in                  │
│                                  │
│ 🟡 Privilege Escalation          │
│ read_* → execute_code → write_*  │
│ Confidence: 78% │ Seen: 12x      │
│ Source: learned ← NEW             │
│                                  │
│ ⚡ LIVE: "Data Exfiltration"     │
│    matched in current session     │
└──────────────────────────────────┘
```

### Demo scenario
1. Show built-in patterns
2. Run Finance Bot session that gets blocked
3. Show new "learned" pattern appeared
4. Run different agent → system catches same pattern earlier
5. Pitch: "In production, patterns share across deployments anonymously"

---

## Frontend Layout

```
┌─sidebar─┬───────────────────────────────────────────────────────┐
│         │  Header: Risk │ Events │ Sessions │ Threats           │
│Sessions │├──────────┬────────────┬────────────┬────────────────┤
│         ││          │ Security   │            │ Tabs:          │
│         ││  Chat    │ Dashboard  │ Taint Flow │ [Pipeline]     │
│         ││  Panel   │ + Threat   │ Diagram    │ [Proof Chain]  │
│         ││          │   Forecast │            │ [Threat Intel] │
│[+ New]  ││          │            │            │                │
└─────────┘└──────────┴────────────┴────────────┴────────────────┘
             25%         25%          25%          25%
```

---

## Deferred: MCP-Native Deployment

**What**: Deploy Sentinel as an MCP server/proxy. Any MCP-compatible agent connects through Sentinel transparently — zero code changes.

**Why deferred**: Architecturally separate from the 4 core features. Requires MCP protocol implementation, proxy layer, and integration testing with real MCP clients. Better as a dedicated phase.

**When**: After V4 is complete and validated.

**Tracking**: This item should be added to the project roadmap/backlog.

---

## Test Strategy

Every feature must be:
1. **Unit tested** — backend logic in isolation
2. **Integration tested** — through the Guardian pipeline
3. **Frontend demonstrable** — visible in the UI with a scripted demo scenario
4. **Existing tests unbroken** — current 145 tests still pass
