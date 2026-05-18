"""
test_t02.py — T02: Layer 1 — Access Control

Attacks covered:
  - Privilege escalation (triage_agent calls propose_wazuh_rule)
  - Confused deputy (enrichment_agent calls propose_wazuh_rule)

Run:
    python tests/test_t02.py
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from tests.common import (
    WAZUH_URL, RawMCP, make_framework,
    TestResult, save_result,
    header, sub, ok, blocked, fail,
)

INJECTED_RULE = (
    "<rule id='99999' level='0'>"
    "<description>Attacker injected rule</description>"
    "<match>.*</match>"
    "</rule>"
)


def run() -> TestResult:
    header(
        "T02",
        "Layer 1: Access Control",
        "Layer 1: Access control",
        ["privilege_escalation", "confused_deputy"],
    )

    # ── WITHOUT FRAMEWORK ────────────────────────────────────────────────────
    sub("WITHOUT FRAMEWORK — triage_agent calls propose_wazuh_rule")
    t0  = time.time()
    raw = RawMCP(WAZUH_URL).connect()
    try:
        result = raw.call("propose_wazuh_rule", {"rule_xml": INJECTED_RULE})
        without = {
            "privilege_escalation": True,
            "call_reached_server":  True,
            "result_preview":       result[:200],
        }
        fail("propose_wazuh_rule called with no role restriction")
    except Exception as e:
        without = {
            "privilege_escalation": False,
            "call_reached_server":  False,
            "server_error":         str(e)[:200],
            "note": "Server returned error but no access control was enforced by client",
        }
        ok("Server returned error (no client-side access control)")
    t_without = time.time() - t0
    raw.disconnect()

    # ── WITH FRAMEWORK ───────────────────────────────────────────────────────
    sub("WITH FRAMEWORK — triage_agent tries propose_wazuh_rule")
    t0      = time.time()
    mcp, fw = make_framework(WAZUH_URL)

    # Test 1: privilege escalation
    priv_blocked = False
    try:
        fw.call_tool("triage_agent", "propose_wazuh_rule",
                     {"rule_xml": INJECTED_RULE})
        fail("Privilege escalation not blocked")
    except PermissionError as e:
        priv_blocked = True
        blocked(f"Privilege escalation blocked: {str(e)[:120]}")

    # Test 2: confused deputy
    sub("WITH FRAMEWORK — enrichment_agent tries propose_wazuh_rule")
    dep_blocked = False
    try:
        fw.call_tool("enrichment_agent", "propose_wazuh_rule",
                     {"rule_xml": INJECTED_RULE})
        fail("Confused deputy not blocked")
    except PermissionError as e:
        dep_blocked = True
        blocked(f"Confused deputy blocked: {str(e)[:120]}")

    t_with = time.time() - t0

    with_ = {
        "privilege_escalation_blocked": priv_blocked,
        "confused_deputy_blocked":      dep_blocked,
        "layer":                        "Layer 1: Access control",
        "audit_outcome":                "blocked_access",
    }

    fw.print_audit_summary()
    mcp.disconnect()

    result = TestResult(
        test_id           = "T02",
        test_name         = "Layer 1: Access Control",
        layer             = "Layer 1: Access control",
        attack_vectors    = ["privilege_escalation", "confused_deputy"],
        without_framework = without,
        with_framework    = with_,
        blocked           = priv_blocked and dep_blocked,
        latency_without   = round(t_without, 3),
        latency_with      = round(t_with, 3),
        latency_overhead  = round(t_with - t_without, 3),
    )
    save_result(result)
    return result


if __name__ == "__main__":
    run()
