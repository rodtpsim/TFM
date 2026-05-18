"""
test_t03.py — T03: Layer 2 — Rate Limiter

Attacks covered:
  - DoS internal / agent in loop
  - Data exfiltration by query flooding

Run:
    python tests/test_t03.py
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

BURST = 22   # above triage_agent limit of 20 calls/60s


def run() -> TestResult:
    header(
        "T03",
        "Layer 2: Rate Limiter",
        "Layer 2: Rate limiter",
        ["dos_internal_agent_loop", "data_exfiltration_query_flooding"],
    )

    # ── WITHOUT FRAMEWORK ────────────────────────────────────────────────────
    sub(f"WITHOUT FRAMEWORK — {BURST} consecutive calls")
    t0      = time.time()
    raw     = RawMCP(WAZUH_URL).connect()
    success = 0
    for _ in range(BURST):
        try:
            raw.call("get_wazuh_alert_summary", {"limit": 1})
            success += 1
        except Exception:
            break
    t_without = time.time() - t0
    raw.disconnect()

    without = {
        "calls_attempted": BURST,
        "calls_succeeded": success,
        "rate_limited":    False,
        "note":            f"All {success} calls reached the MCP server without throttling",
    }
    fail(f"{success}/{BURST} calls succeeded with no rate limit")

    # ── WITH FRAMEWORK ───────────────────────────────────────────────────────
    sub(f"WITH FRAMEWORK — same {BURST} calls through triage_agent role")
    t0      = time.time()
    mcp, fw = make_framework(WAZUH_URL)

    success_fw = 0
    blocked_at = None
    for i in range(BURST):
        try:
            fw.call_tool("triage_agent", "get_wazuh_alert_summary", {"limit": 1})
            success_fw += 1
        except RuntimeError as e:
            blocked_at = i + 1
            blocked(f"Rate limit triggered at call {blocked_at}/{BURST}: {str(e)[:100]}")
            break

    t_with = time.time() - t0

    if blocked_at is None:
        fail(f"Rate limit not triggered after {BURST} calls")

    with_ = {
        "calls_attempted": BURST,
        "calls_succeeded": success_fw,
        "blocked_at_call": blocked_at,
        "rate_limited":    blocked_at is not None,
        "layer":           "Layer 2: Rate limiter",
        "limit_config":    "20 calls / 60s for triage_agent",
    }

    fw.print_audit_summary()
    mcp.disconnect()

    # Overhead: per-call latency difference
    per_call_without = t_without / max(success, 1)
    per_call_with    = t_with / max(success_fw, 1)
    overhead         = per_call_with - per_call_without

    result = TestResult(
        test_id           = "T03",
        test_name         = "Layer 2: Rate Limiter",
        layer             = "Layer 2: Rate limiter",
        attack_vectors    = ["dos_internal_agent_loop",
                             "data_exfiltration_query_flooding"],
        without_framework = without,
        with_framework    = with_,
        blocked           = blocked_at is not None,
        latency_without   = round(t_without, 3),
        latency_with      = round(t_with, 3),
        latency_overhead  = round(overhead, 3),
        notes             = f"Burst of {BURST} calls. Limit: 20/60s for triage_agent.",
    )
    save_result(result)
    return result


if __name__ == "__main__":
    run()
