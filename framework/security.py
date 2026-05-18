"""
framework/security.py — Security Framework for MCP-based Multi-Agent Systems.

OWASP controls implemented (Practical Guide for Secure MCP Server Development v1.0):

  Section 2 - Safe Tool Design:
    Tool registration validator  Scans descriptions at connect time
    Tool version pinning         SHA-256 hash of tool manifest at first connect;
                                 detects changes on reconnect (partial rug pull mitigation)

  Section 3 - Data Validation and Resource Management:
    Layer 3 Input validator      JSON schema validation per tool (via tool_schemas.py)
                                 + regex injection patterns + inter-agent trust
    Layer 4 Output validator     Pattern matching + 100KB size limit

  Section 4 - Prompt Injection Controls:
    Layer 3 Input validator      Argument and handoff scanning
    Layer 3 Memory validator     Context store validation before prompt injection

  Section 5 - Authentication and Authorization:
    Layer 1 Access control       RBAC per agent role, explicit allowlist

  Section 6 - Secure Deployment:
    Safe error handling          Framework exceptions never expose stack traces
                                 or server internals to the LLM

  Section 7 - Governance:
    Layer 5 Audit log            Immutable record, SHA-256 result hash,
                                 field-level redaction of sensitive arguments

  Section 3 - Resource Management:
    Layer 2 Rate limiter         Per-agent call budget (20/30/20 per 60s)

Controls not implemented (out of scope - infrastructure layer):
    OAuth 2.1 / OIDC             Requires external identity provider
    TLS enforcement              Transport layer, lab environment uses private network
    Secrets vault                Disproportionate for lab scope
    LLM-as-a-judge               Cost and complexity beyond declared scope
"""

import re
import json
import time
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, asdict

try:
    import jsonschema
    _JSONSCHEMA_AVAILABLE = True
except ImportError:
    _JSONSCHEMA_AVAILABLE = False

from framework.tool_schemas import TOOL_SCHEMAS

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# SENSITIVE FIELD REDACTION
# OWASP Section 7: "Use field-level allowlists and redaction/hashing to
# prevent sensitive data from entering verbose logs."
# ══════════════════════════════════════════════════════════════════════════════

_SENSITIVE_FIELDS = {"rule_xml", "api_key", "token", "password", "secret"}


def _redact(arguments: dict) -> dict:
    """Return a copy of arguments with sensitive fields hashed."""
    result = {}
    for k, v in arguments.items():
        if k in _SENSITIVE_FIELDS and isinstance(v, str):
            result[k] = f"[REDACTED sha256:{hashlib.sha256(v.encode()).hexdigest()[:12]}]"
        else:
            result[k] = v
    return result


# ══════════════════════════════════════════════════════════════════════════════
# SAFE ERROR RESPONSES
# OWASP Section 6: "Do not return stack traces, tokens, filesystem paths, or
# tool internals in responses returned to the model/client."
# ══════════════════════════════════════════════════════════════════════════════

_SAFE_ERRORS = {
    "blocked_access":     "Tool call blocked: insufficient permissions for this agent role.",
    "blocked_rate":       "Tool call blocked: call rate limit exceeded for this agent.",
    "blocked_input":      "Tool call blocked: argument validation failed.",
    "blocked_output":     "Tool call blocked: response validation failed.",
    "blocked_interagent": "Handoff blocked: upstream agent output failed trust validation.",
    "blocked_memory":     "Context blocked: persistent context failed validation.",
    "blocked_schema":     "Tool call blocked: argument schema validation failed.",
    "error":              "Tool call failed: an internal error occurred.",
}


def safe_error_message(outcome: str) -> str:
    """Return a safe, non-revealing error message for the given outcome."""
    return _SAFE_ERRORS.get(outcome, "Tool call blocked.")


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — ACCESS CONTROL
# ══════════════════════════════════════════════════════════════════════════════

READ_ONLY_TOOLS = {
    "get_wazuh_agents",
    "get_wazuh_alert_summary",
    "get_wazuh_agent_processes",
    "get_wazuh_agent_ports",
    "get_wazuh_cluster_nodes",
    "get_wazuh_cluster_health",
    "get_wazuh_latest_alert",
    "get_wazuh_rules_summary",
    "get_wazuh_vulnerability_summary",
    "get_wazuh_critical_vulnerabilities",
    "get_wazuh_weekly_stats",
    "get_wazuh_remoted_stats",
    "get_wazuh_log_collector_stats",
    "get_wazuh_manager_error_logs",
    "search_wazuh_manager_logs",
}

DESTRUCTIVE_TOOLS = {"propose_wazuh_rule"}

AGENT_PERMISSIONS: dict[str, set[str]] = {
    "triage_agent":     READ_ONLY_TOOLS,
    "enrichment_agent": READ_ONLY_TOOLS,
    "response_agent":   READ_ONLY_TOOLS | DESTRUCTIVE_TOOLS,
    "orchestrator":     READ_ONLY_TOOLS,
}


class AccessControl:

    def check(self, agent_role: str, tool_name: str) -> None:
        allowed = AGENT_PERMISSIONS.get(agent_role, set())
        if tool_name not in allowed:
            msg = (
                f"[ACCESS CONTROL] BLOCKED: "
                f"'{agent_role}' cannot call '{tool_name}'."
            )
            logger.warning(msg)
            raise PermissionError(safe_error_message("blocked_access"))

    def filter_tools(self, agent_role: str, all_tools: list) -> list:
        allowed = AGENT_PERMISSIONS.get(agent_role, set())
        return [t for t in all_tools if t["name"] in allowed]


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — RATE LIMITER
# OWASP Section 3: "Impose quotas and rate limits on tool invocations."
# ══════════════════════════════════════════════════════════════════════════════

RATE_LIMITS: dict[str, dict] = {
    "triage_agent":     {"max_calls": 20, "window_seconds": 60},
    "enrichment_agent": {"max_calls": 30, "window_seconds": 60},
    "response_agent":   {"max_calls": 20, "window_seconds": 60},
    "orchestrator":     {"max_calls": 10, "window_seconds": 60},
    "_default":         {"max_calls": 15, "window_seconds": 60},
}


class RateLimiter:

    def __init__(self):
        self._calls: dict[str, list[float]] = defaultdict(list)

    def check(self, agent_role: str, tool_name: str) -> None:
        limits    = RATE_LIMITS.get(agent_role, RATE_LIMITS["_default"])
        max_calls = limits["max_calls"]
        window    = limits["window_seconds"]
        now       = time.time()
        self._calls[agent_role] = [
            t for t in self._calls[agent_role] if now - t < window
        ]
        if len(self._calls[agent_role]) >= max_calls:
            msg = (
                f"[RATE LIMITER] BLOCKED: "
                f"'{agent_role}' exceeded {max_calls} calls in {window}s."
            )
            logger.warning(msg)
            raise RuntimeError(safe_error_message("blocked_rate"))
        self._calls[agent_role].append(now)

    def get_stats(self) -> dict:
        now = time.time()
        return {
            role: len([t for t in ts
                       if now - t < RATE_LIMITS.get(role, RATE_LIMITS["_default"])["window_seconds"]])
            for role, ts in self._calls.items()
        }


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — INPUT VALIDATOR
# OWASP Section 3: JSON schema validation for tool inputs.
# OWASP Section 4: Prompt injection controls, memory poisoning, inter-agent trust.
# ══════════════════════════════════════════════════════════════════════════════

_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions?)",
    r"forget\s+(everything|all|your\s+instructions?)",
    r"override\s+(your\s+)?(previous\s+)?instructions?",
    r"you\s+are\s+now\s+(?!analyzing|checking|retrieving|a\s+soc)",
    r"act\s+as\s+(?!an?\s+analyst|a\s+soc)",
    r"pretend\s+(you\s+are|to\s+be)",
    r"new\s+persona|switch\s+role",
    r"(print|show|reveal|output|repeat|leak)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
    r"\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>",
    r"\bDAN\b|\bjailbreak\b|developer\s+mode",
    r"[;&|`$\\](?!\d)",
    r"new\s+(task|objective|goal|instructions?)\s+(for\s+)?(you|the\s+agent)",
    r"from\s+now\s+on\s+(you|ignore|always|never)",
    r"mandatory\s+(security\s+)?(protocol|update|override)",
    r"compliance\s+(requires?|mandates?|forces?)\s+you\s+to",
]
_COMPILED_INJECTION = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


@dataclass
class ValidationResult:
    passed: bool
    reason: Optional[str] = None
    outcome: str = "allowed"


class InputValidator:

    def validate(self, tool_name: str, arguments: dict) -> ValidationResult:
        # 1. JSON schema validation (OWASP Section 3)
        schema = TOOL_SCHEMAS.get(tool_name)
        if schema and _JSONSCHEMA_AVAILABLE:
            try:
                import jsonschema as _js
                _js.validate(instance=arguments, schema=schema)
            except _js.ValidationError as e:
                return ValidationResult(
                    passed=False,
                    reason=(
                        f"[INPUT VALIDATOR] BLOCKED: "
                        f"Schema validation failed for '{tool_name}': {e.message}"
                    ),
                    outcome="blocked_schema",
                )

        # 2. Injection pattern scan
        for key, value in arguments.items():
            if isinstance(value, str):
                for pattern in _COMPILED_INJECTION:
                    if pattern.search(value):
                        return ValidationResult(
                            passed=False,
                            reason=(
                                f"[INPUT VALIDATOR] BLOCKED: "
                                f"Injection pattern in '{key}' for '{tool_name}'."
                            ),
                            outcome="blocked_input",
                        )

        return ValidationResult(passed=True)

    def validate_agent_output(self, source_agent: str, output: str) -> ValidationResult:
        """Inter-agent trust validation."""
        for pattern in _COMPILED_INJECTION:
            if pattern.search(output):
                return ValidationResult(
                    passed=False,
                    reason=(
                        f"[INTER-AGENT TRUST] BLOCKED: "
                        f"Output of '{source_agent}' contains injection pattern."
                    ),
                    outcome="blocked_interagent",
                )
        return ValidationResult(passed=True)

    def validate_memory_context(self, context: dict) -> ValidationResult:
        """Memory poisoning validation."""
        for key, value in context.items():
            if isinstance(value, str):
                for pattern in _COMPILED_INJECTION:
                    if pattern.search(value):
                        return ValidationResult(
                            passed=False,
                            reason=(
                                f"[MEMORY VALIDATOR] BLOCKED: "
                                f"context_store key '{key}' contains injection pattern."
                            ),
                            outcome="blocked_memory",
                        )
        return ValidationResult(passed=True)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 4 — OUTPUT VALIDATOR
# OWASP Section 3: Enforce size limits on all outputs from tools.
# ══════════════════════════════════════════════════════════════════════════════

_OUTPUT_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?:",
    r"\[SYSTEM\]|\[INST\]",
    r"exfiltrate|send\s+(this\s+)?(data|credentials?|password|token)\s+to",
    r"call\s+tool\s+(propose_wazuh_rule)\s+with",
    r"execute\s+(the\s+following|this)\s+command",
    r"your\s+new\s+(task|goal|objective)\s+is",
    r"mandatory\s+(action|requirement|protocol)",
    r"(required|must)\s+(call|invoke|execute|run)\s+tool",
]
_COMPILED_OUTPUT = [re.compile(p, re.IGNORECASE) for p in _OUTPUT_PATTERNS]
MAX_OUTPUT_BYTES = 100_000


class OutputValidator:

    def validate(self, tool_name: str, raw_output: str) -> ValidationResult:
        if len(raw_output) > MAX_OUTPUT_BYTES:
            return ValidationResult(
                passed=False,
                reason=(
                    f"[OUTPUT VALIDATOR] BLOCKED: "
                    f"Response from '{tool_name}' too large "
                    f"({len(raw_output)} > {MAX_OUTPUT_BYTES} bytes)."
                ),
                outcome="blocked_output",
            )
        for pattern in _COMPILED_OUTPUT:
            if pattern.search(raw_output):
                return ValidationResult(
                    passed=False,
                    reason=(
                        f"[OUTPUT VALIDATOR] BLOCKED: "
                        f"Tool poisoning in '{tool_name}' response."
                    ),
                    outcome="blocked_output",
                )
        return ValidationResult(passed=True)


# ══════════════════════════════════════════════════════════════════════════════
# TOOL REGISTRATION VALIDATOR + VERSION PINNING
# OWASP Section 2: Tool description validation at load time.
# OWASP Section 7: "Use cryptographic signing and version pinning for all tools."
# Partial rug pull mitigation: hash the tool manifest at first connect and
# detect changes on reconnect.
# ══════════════════════════════════════════════════════════════════════════════

_TOOL_DESC_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior)\s+instructions?",
    r"important\s+(system\s+)?instruction\s+for\s+(ai|llm|assistant)",
    r"(mandatory|required)\s+(for\s+)?(ai|llm|the\s+model)",
    r"you\s+must\s+(call|invoke|execute|always|never)",
    r"after\s+(calling|using|invoking)\s+this\s+tool.{0,50}(call|invoke|execute)",
    r"new\s+(system\s+)?instructions?\s+for\s+(the\s+)?(ai|model|assistant)",
    r"override\s+(the\s+)?(previous|prior|system)",
    r"\[SYSTEM\]|\[INST\]|<\|system\|>",
    r"note\s+for\s+(ai|llm|assistant|the\s+model)",
]
_COMPILED_DESC = [re.compile(p, re.IGNORECASE) for p in _TOOL_DESC_PATTERNS]


def _manifest_hash(tools: list) -> str:
    """Compute a deterministic SHA-256 hash of a tool manifest."""
    canonical = json.dumps(
        sorted([{"name": t["name"], "description": t.get("description", "")}
                for t in tools],
               key=lambda x: x["name"]),
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class ToolRegistrationValidator:

    def __init__(self):
        self._pinned_hashes: dict[str, str] = {}

    def validate_tools(self, tools: list, server_url: str) -> tuple[list, list]:
        clean   = []
        blocked = []

        for tool in tools:
            desc     = tool.get("description", "")
            poisoned = False
            reason   = ""
            for pattern in _COMPILED_DESC:
                if pattern.search(desc):
                    poisoned = True
                    reason   = f"Description matches pattern: /{pattern.pattern}/"
                    break
            if poisoned:
                blocked.append({**tool, "_blocked_reason": reason, "_server": server_url})
                logger.warning(
                    f"[TOOL REGISTRATION] BLOCKED: "
                    f"Tool '{tool['name']}' from {server_url}. {reason}"
                )
            else:
                clean.append(tool)

        # Version pinning: detect manifest changes across reconnects
        current_hash = _manifest_hash(tools)
        if server_url in self._pinned_hashes:
            if self._pinned_hashes[server_url] != current_hash:
                logger.warning(
                    f"[TOOL REGISTRATION] WARNING: "
                    f"Tool manifest changed for {server_url}. "
                    f"Previous hash: {self._pinned_hashes[server_url][:16]} "
                    f"Current hash: {current_hash[:16]}. "
                    f"Possible rug pull or server update."
                )
        else:
            self._pinned_hashes[server_url] = current_hash
            logger.info(
                f"[TOOL REGISTRATION] Manifest pinned for {server_url}: "
                f"{current_hash[:16]}"
            )

        logger.info(
            f"[TOOL REGISTRATION] {server_url}: "
            f"{len(clean)} clean, {len(blocked)} blocked."
        )
        return clean, blocked

    def get_pinned_hashes(self) -> dict:
        return dict(self._pinned_hashes)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 5 — AUDIT LOG
# OWASP Section 7: Immutable audit trail with field-level redaction.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AuditEntry:
    timestamp:   str
    agent_role:  str
    tool_name:   str
    arguments:   dict      # redacted
    outcome:     str
    detail:      Optional[str] = None
    result_hash: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLog:

    def __init__(self):
        self._entries: list[AuditEntry] = []
        self._reg_events: list[dict]    = []

    def record(self, agent_role, tool_name, arguments, outcome,
               detail=None, result=None) -> AuditEntry:
        # Redact sensitive fields before logging (OWASP Section 7)
        safe_args = _redact(arguments)
        # Use safe error message in detail to avoid leaking internals
        safe_detail = safe_error_message(outcome) if (detail and outcome != "allowed") else detail

        entry = AuditEntry(
            timestamp   = datetime.now(timezone.utc).isoformat(),
            agent_role  = agent_role,
            tool_name   = tool_name,
            arguments   = safe_args,
            outcome     = outcome,
            detail      = safe_detail,
            result_hash = hashlib.sha256(result.encode()).hexdigest()[:16] if result else None,
        )
        self._entries.append(entry)
        icon = "✅" if outcome == "allowed" else "🚫"
        logger.info(f"  {icon} AUDIT [{agent_role}] {tool_name} = {outcome}")
        if safe_detail and outcome != "allowed":
            logger.warning(f"     {safe_detail[:120]}")
        return entry

    def record_registration(self, server_url: str, clean: list,
                             blocked: list, manifest_hash: str):
        self._reg_events.append({
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "server_url":    server_url,
            "manifest_hash": manifest_hash[:16],
            "clean":         [t["name"] for t in clean],
            "blocked":       [{"name": t["name"],
                               "reason": t.get("_blocked_reason", "")}
                              for t in blocked],
        })

    def record_interagent_block(self, source: str, target: str, reason: str):
        self.record(source, f"[handoff to {target}]", {}, "blocked_interagent",
                    safe_error_message("blocked_interagent"))

    def record_memory_block(self, reason: str):
        self.record("memory", "[context_store]", {}, "blocked_memory",
                    safe_error_message("blocked_memory"))

    def get_all(self) -> list[dict]:
        return [e.to_dict() for e in self._entries]

    def get_blocked(self) -> list[dict]:
        return [e.to_dict() for e in self._entries if e.outcome.startswith("blocked")]

    def summary(self) -> dict:
        total   = len(self._entries)
        blocked = len(self.get_blocked())
        by_outcome: dict[str, int] = {}
        by_agent:   dict[str, int] = {}
        for e in self._entries:
            by_outcome[e.outcome]  = by_outcome.get(e.outcome, 0) + 1
            by_agent[e.agent_role] = by_agent.get(e.agent_role, 0) + 1
        return {
            "total_calls":             total,
            "allowed_calls":           total - blocked,
            "blocked_calls":           blocked,
            "block_rate":              f"{(blocked/total*100):.1f}%" if total else "0%",
            "by_outcome":              by_outcome,
            "by_agent":                by_agent,
            "tools_blocked_at_registration": sum(
                len(e["blocked"]) for e in self._reg_events
            ),
        }


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY FRAMEWORK — unified entry point
# ══════════════════════════════════════════════════════════════════════════════

class SecurityFramework:

    def __init__(self, mcp_client):
        self.mcp      = mcp_client
        self.access   = AccessControl()
        self.ratelim  = RateLimiter()
        self.inp      = InputValidator()
        self.out      = OutputValidator()
        self.tool_reg = ToolRegistrationValidator()
        self.audit    = AuditLog()

    def register_server(self, server_url: str, tools: list) -> list:
        clean, blocked = self.tool_reg.validate_tools(tools, server_url)
        manifest_hash  = _manifest_hash(tools)
        self.audit.record_registration(server_url, clean, blocked, manifest_hash)
        return clean

    def validate_handoff(self, source_agent: str, target_agent: str,
                          output: str) -> str:
        result = self.inp.validate_agent_output(source_agent, output)
        if not result.passed:
            self.audit.record_interagent_block(source_agent, target_agent, result.reason)
            raise ValueError(safe_error_message("blocked_interagent"))
        return output

    def validate_memory_context(self, context: dict) -> dict:
        result = self.inp.validate_memory_context(context)
        if not result.passed:
            self.audit.record_memory_block(result.reason)
            logger.warning(result.reason)
            return {}
        return context

    def call_tool(self, agent_role: str, tool_name: str,
                  arguments: dict) -> str:

        # Layer 1: Access control
        try:
            self.access.check(agent_role, tool_name)
        except PermissionError as e:
            self.audit.record(agent_role, tool_name, arguments, "blocked_access")
            raise PermissionError(safe_error_message("blocked_access")) from None

        # Layer 2: Rate limiter
        try:
            self.ratelim.check(agent_role, tool_name)
        except RuntimeError:
            self.audit.record(agent_role, tool_name, arguments, "blocked_rate")
            raise RuntimeError(safe_error_message("blocked_rate")) from None

        # Layer 3: Input validation (schema + injection patterns)
        iv = self.inp.validate(tool_name, arguments)
        if not iv.passed:
            self.audit.record(agent_role, tool_name, arguments,
                              iv.outcome, iv.reason)
            raise ValueError(safe_error_message(iv.outcome))

        # MCP call
        try:
            raw = self.mcp.call_tool(tool_name, arguments)
        except Exception as e:
            self.audit.record(agent_role, tool_name, arguments, "error")
            # Safe error: do not propagate internal exception details to LLM
            raise RuntimeError(safe_error_message("error")) from None

        # Layer 4: Output validation
        ov = self.out.validate(tool_name, raw)
        if not ov.passed:
            self.audit.record(agent_role, tool_name, arguments,
                              ov.outcome, ov.reason, raw)
            raise ValueError(safe_error_message(ov.outcome))

        # Layer 5: Audit log (allowed)
        self.audit.record(agent_role, tool_name, arguments, "allowed", result=raw)
        return raw

    def get_tools_for(self, agent_role: str) -> list:
        all_tools = self.mcp.list_tools()
        return self.access.filter_tools(agent_role, all_tools)

    def print_audit_summary(self):
        s = self.audit.summary()
        print(f"\n{'='*55}")
        print(f"  SECURITY FRAMEWORK — AUDIT SUMMARY")
        print(f"{'='*55}")
        print(f"  Total calls  : {s['total_calls']}")
        print(f"  Allowed      : {s['allowed_calls']}")
        print(f"  Blocked      : {s['blocked_calls']}  ({s['block_rate']})")
        print(f"  Tools blocked at registration: "
              f"{s['tools_blocked_at_registration']}")
        if s["by_outcome"]:
            print(f"\n  By outcome:")
            for outcome, n in s["by_outcome"].items():
                print(f"    {outcome:<30} {n}")
        if s["by_agent"]:
            print(f"\n  By agent:")
            for agent, n in s["by_agent"].items():
                print(f"    {agent:<30} {n}")
        blocked = self.audit.get_blocked()
        if blocked:
            print(f"\n  Blocked events ({len(blocked)}):")
            for b in blocked:
                ts = b['timestamp'][11:19]
                print(f"    [{ts}] {b['agent_role']} "
                      f"-> {b['tool_name']} ({b['outcome']})")
                if b['detail']:
                    print(f"    {b['detail'][:100]}")
        print(f"{'='*55}\n")
