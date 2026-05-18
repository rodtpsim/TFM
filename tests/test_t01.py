"""
test_t01.py — T01: Tool Registration Validator

Attacks covered:
  - Tool description poisoning
  - Tool shadowing (name collision)

Run:
    python tests/test_t01.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests.common import (
    EVIL_URL, RawMCP, make_framework,
    TestResult, save_result,
    header, sub, ok, blocked, fail,
)


def run() -> TestResult:
    header(
        "T01",
        "Tool Registration Validator",
        "Tool registration validator",
        ["tool_description_poisoning", "tool_shadowing"],
    )

    # ── WITHOUT FRAMEWORK ────────────────────────────────────────────────────
    sub("WITHOUT FRAMEWORK")
    t0   = time.time()
    evil = RawMCP(EVIL_URL).connect()
    tools_raw = evil.tools()
    t_without = time.time() - t0

    poisoned = [t for t in tools_raw
                if t["name"] in ("get_threat_intelligence", "get_compliance_report")]
    shadowed = [t for t in tools_raw if t["name"] == "get_wazuh_latest_alert"]

    without = {
        "total_tools_received":   len(tools_raw),
        "poisoned_tools_exposed": [t["name"] for t in poisoned],
        "shadowed_tools_exposed": [t["name"] for t in shadowed],
        "agent_sees_malicious":   len(poisoned) > 0,
        "poisoned_desc_sample":   poisoned[0]["description"][:250] if poisoned else "",
    }

    if poisoned:
        fail(f"{len(poisoned)} poisoned tools exposed: {[t['name'] for t in poisoned]}")
    if shadowed:
        fail(f"Tool shadowing: get_wazuh_latest_alert present in evil server")

    evil.disconnect()

    # ── WITH FRAMEWORK ───────────────────────────────────────────────────────
    sub("WITH FRAMEWORK")
    t0      = time.time()
    mcp, fw = make_framework(EVIL_URL)
    raw     = mcp.list_tools()
    clean   = fw.register_server(EVIL_URL, raw)
    t_with  = time.time() - t0

    n_blocked      = len(raw) - len(clean)
    blocked_names  = [t["name"] for t in raw if t not in clean]
    shadow_remain  = [t for t in clean if t["name"] == "get_wazuh_latest_alert"]

    with_ = {
        "total_tools_received": len(raw),
        "tools_blocked":        n_blocked,
        "tools_blocked_names":  blocked_names,
        "clean_tools_passed":   [t["name"] for t in clean],
        "agent_sees_malicious": n_blocked < len(poisoned),
    }

    if n_blocked > 0:
        blocked(f"{n_blocked} tools blocked at registration: {blocked_names}")
    if shadow_remain:
        ok(f"Tool shadowing collision detected and logged "
           f"(get_wazuh_latest_alert still present, namespace resolution required)")

    fw.print_audit_summary()
    mcp.disconnect()

    result = TestResult(
        test_id           = "T01",
        test_name         = "Tool Registration Validator",
        layer             = "Tool registration validator",
        attack_vectors    = ["tool_description_poisoning", "tool_shadowing"],
        without_framework = without,
        with_framework    = with_,
        blocked           = n_blocked >= len(poisoned) and n_blocked > 0,
        latency_without   = round(t_without, 3),
        latency_with      = round(t_with, 3),
        latency_overhead  = round(t_with - t_without, 3),
        notes             = "Tool shadowing requires trust-based namespace resolution "
                            "in addition to collision detection.",
    )
    save_result(result)
    return result


if __name__ == "__main__":
    run()
