"""
tests/common.py — Shared utilities for all test scripts.
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

WAZUH_URL    = os.getenv("MCP_SERVER_URL", "http://192.168.56.110:8080/mcp")
EVIL_URL     = os.getenv("EVIL_MCP_URL",   "http://127.0.0.1:8089/mcp")
RESULTS_FILE = os.getenv("RESULTS_FILE",   "test_results.jsonl")


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class TestResult:
    test_id:           str
    test_name:         str
    layer:             str
    attack_vectors:    list
    without_framework: dict
    with_framework:    dict
    blocked:           bool
    latency_without:   float
    latency_with:      float
    latency_overhead:  float
    notes:             str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = datetime.now(timezone.utc).isoformat()
        return d


def save_result(result: TestResult):
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")
    print(f"\n  Result saved to {RESULTS_FILE}")


# ── Raw MCP client (no framework) ─────────────────────────────────────────────

class RawMCP:
    """Direct MCP client with no security checks. Used for without-framework tests."""

    def __init__(self, url: str):
        self.url = url
        self.s   = requests.Session()
        self.sid = None
        self.rid = 1

    def _headers(self):
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["MCP-Session-Id"] = self.sid
        return h

    def _sse(self, text):
        for block in text.replace("\r\n", "\n").split("\n\n"):
            lines = [l[5:].lstrip() for l in block.split("\n")
                     if l.strip().startswith("data:")]
            if lines:
                try:
                    return json.loads("\n".join(lines))
                except Exception:
                    pass
        raise RuntimeError(f"No JSON in SSE: {text[:200]}")

    def _post(self, payload):
        r = self.s.post(self.url, json=payload,
                        headers=self._headers(), timeout=30)
        r.raise_for_status()
        if sid := r.headers.get("MCP-Session-Id"):
            self.sid = sid
        if not r.text.strip():
            return {}
        return (self._sse(r.text)
                if "event-stream" in r.headers.get("Content-Type", "")
                else r.json())

    def _rpc(self, method, params=None):
        p = {"jsonrpc": "2.0", "id": self.rid,
             "method": method, "params": params or {}}
        self.rid += 1
        return self._post(p)

    def connect(self):
        self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities":    {},
            "clientInfo":      {"name": "test-runner", "version": "1.0"},
        })
        self._post({"jsonrpc": "2.0",
                    "method": "notifications/initialized", "params": {}})
        return self

    def tools(self) -> list:
        return self._rpc("tools/list", {}).get("result", {}).get("tools", [])

    def call(self, name: str, args: dict = {}) -> str:
        r       = self._rpc("tools/call", {"name": name, "arguments": args})
        content = r.get("result", {}).get("content", [])
        return "\n".join(c.get("text", "")
                         for c in content if c.get("type") == "text")

    def disconnect(self):
        self.s.close()


# ── Framework client factory ──────────────────────────────────────────────────

def make_framework(url: str = WAZUH_URL):
    """Connect an MCPClient and wrap it in a SecurityFramework."""
    # Add parent dir to path so imports work from tests/
    parent = os.path.dirname(os.path.dirname(__file__))
    if parent not in sys.path:
        sys.path.insert(0, parent)

    from mcp.client import MCPClient
    from framework.security import SecurityFramework

    mcp = MCPClient(url)
    mcp.connect()
    return mcp, SecurityFramework(mcp)


# ── Console helpers ───────────────────────────────────────────────────────────

def header(test_id, name, layer, attacks):
    print(f"\n{'='*60}")
    print(f"  {test_id}: {name}")
    print(f"  Layer   : {layer}")
    print(f"  Attacks : {', '.join(attacks)}")
    print(f"{'='*60}")

def sub(label):
    print(f"\n  [{label}]")

def ok(msg):
    print(f"    OK      {msg}")

def blocked(msg):
    print(f"    BLOCKED {msg}")

def fail(msg):
    print(f"    FAIL    {msg}")
