"""
mcp/client.py — Cliente MCP HTTP para mcp-server-wazuh.
Transporte: POST /mcp → respuesta SSE en el mismo body.
"""

import json
import os
import logging
from typing import Optional
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

MCP_URL = os.getenv("MCP_SERVER_URL", "http://192.168.56.110:8080/mcp")


class MCPClient:

    def __init__(self, url: str = MCP_URL):
        self.url        = url
        self.session    = requests.Session()
        self.session_id: Optional[str] = None
        self._rid       = 1
        self._ready     = False
        self._tools     = None

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.session_id:
            h["MCP-Session-Id"] = self.session_id
        return h

    def _parse_sse(self, text: str) -> dict:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        for block in text.split("\n\n"):
            lines = [l[5:].lstrip() for l in block.split("\n")
                     if l.strip().startswith("data:")]
            if lines:
                try:
                    return json.loads("\n".join(lines))
                except json.JSONDecodeError:
                    pass
        raise RuntimeError(f"No JSON in SSE:\n{text[:200]}")

    def _post(self, payload: dict) -> dict:
        r = self.session.post(self.url, json=payload,
                              headers=self._headers(), timeout=90)
        r.raise_for_status()
        if sid := r.headers.get("MCP-Session-Id"):
            self.session_id = sid
        if not r.text.strip():
            return {}
        if "event-stream" in r.headers.get("Content-Type", ""):
            return self._parse_sse(r.text)
        return r.json()

    def _rpc(self, method: str, params: dict = None) -> dict:
        p = {"jsonrpc": "2.0", "id": self._rid,
             "method": method, "params": params or {}}
        self._rid += 1
        return self._post(p)

    def _notify(self, method: str) -> None:
        self._post({"jsonrpc": "2.0", "method": method, "params": {}})

    def connect(self) -> None:
        if self._ready:
            return
        r = self._rpc("initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities":    {},
            "clientInfo":      {"name": "soc-arch", "version": "1.0"},
        })
        if "error" in r:
            raise RuntimeError(f"MCP init failed: {r['error']}")
        self._notify("notifications/initialized")
        self._ready = True
        logger.info(f"MCP connected: {r.get('result',{}).get('serverInfo',{})}")

    def disconnect(self) -> None:
        self.session.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def list_tools(self) -> list:
        if self._tools is not None:
            return self._tools
        self.connect()
        r = self._rpc("tools/list", {})
        if "error" in r:
            raise RuntimeError(f"tools/list failed: {r['error']}")
        raw = r.get("result", {}).get("tools", [])
        self._tools = [
            {
                "name":        t["name"],
                "description": t.get("description", ""),
                "parameters":  _normalize_schema(t.get("inputSchema")),
            }
            for t in raw
        ]
        logger.info(f"Tools: {[t['name'] for t in self._tools]}")
        return self._tools

    def call_tool(self, name: str, arguments: dict = {}) -> str:
        self.connect()
        r = self._rpc("tools/call", {"name": name, "arguments": arguments})
        if "error" in r:
            raise RuntimeError(f"Tool '{name}' error: {r['error']}")
        content = r.get("result", {}).get("content", [])
        parts   = [c.get("text", "") for c in content if c.get("type") == "text"]
        text    = "\n\n".join(parts).strip()
        return f"[MCP ERROR]\n{text}" if r.get("result", {}).get("isError") else text


def _normalize_schema(schema: Optional[dict]) -> dict:
    if not schema:
        return {"type": "object", "properties": {}, "additionalProperties": False}
    s = dict(schema)
    s["type"] = "object"
    s.setdefault("properties", {})
    s.setdefault("additionalProperties", False)
    for prop in s["properties"].values():
        if isinstance(prop.get("type"), list):
            non_null = [t for t in prop["type"] if t != "null"]
            prop["type"] = non_null[0] if non_null else "string"
        if prop.get("nullable") and "type" not in prop:
            prop["type"] = "string"
    s.pop("$schema", None)
    s.pop("title", None)
    s.pop("description", None)
    return s
