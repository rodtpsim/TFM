"""
memory/store.py — Memoria compartida entre agentes, persistente en disco.

Tres ficheros JSON en ./memory_data/:
  alert_history.json    Historial de alertas analizadas.
  agent_knowledge.json  Conocimiento acumulado sobre hosts.
  context_store.json    Instrucciones persistentes leídas por todos los agentes.
                        ← SUPERFICIE DE MEMORY POISONING
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


class MemoryStore:

    def __init__(self, data_dir: str = "./memory_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        self._alerts  = self.data_dir / "alert_history.json"
        self._agents  = self.data_dir / "agent_knowledge.json"
        self._context = self.data_dir / "context_store.json"
        for path, default in [
            (self._alerts,  []),
            (self._agents,  {}),
            (self._context, {}),
        ]:
            if not path.exists():
                self._write(path, default)
        logger.info(f"[MEMORY] Store ready: {self.data_dir}")

    def _read(self, path: Path):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return [] if path == self._alerts else {}

    def _write(self, path: Path, data):
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Alert history ─────────────────────────────────────────────────────────

    def save_alert(self, alert_id: str, agent_name: str,
                   triage: dict, enrichment: dict) -> None:
        history = self._read(self._alerts)
        history.append({
            "alert_id":    alert_id,
            "timestamp":   self._now(),
            "agent_name":  agent_name,
            "severity":    triage.get("severity", "unknown"),
            "threat_type": triage.get("threat_type", "unknown"),
            "is_fp":       triage.get("is_false_positive", False),
            "escalated":   triage.get("escalate", False),
            "triage":      triage,
            "enrichment":  enrichment,
        })
        self._write(self._alerts, history)
        logger.info(f"[MEMORY] Alert saved: {alert_id} | "
                    f"{triage.get('severity')} | {agent_name}")

    def get_recent_alerts(self, limit: int = 5,
                          agent_name: str = None) -> list:
        history = self._read(self._alerts)
        if agent_name:
            history = [a for a in history
                       if a.get("agent_name") == agent_name]
        return list(reversed(history[-limit:]))

    # ── Agent knowledge ───────────────────────────────────────────────────────

    def upsert_agent_knowledge(self, agent_name: str, ip: str,
                                cves: list, risk_level: str,
                                notes: str = "") -> None:
        knowledge = self._read(self._agents)
        knowledge[agent_name] = {
            "ip":         ip,
            "last_seen":  self._now(),
            "cves":       cves,
            "risk_level": risk_level,
            "notes":      notes,
        }
        self._write(self._agents, knowledge)
        logger.info(f"[MEMORY] Agent updated: {agent_name} | {risk_level}")

    def get_agent_knowledge(self, agent_name: str) -> dict | None:
        return self._read(self._agents).get(agent_name)

    # ── Context store — superficie de memory poisoning ────────────────────────

    def set_context(self, key: str, value: str,
                    source: str = "system") -> None:
        context = self._read(self._context)
        context[key] = {
            "value":      value,
            "updated_at": self._now(),
            "source":     source,
        }
        self._write(self._context, context)
        logger.info(f"[MEMORY] Context set: '{key}' (source={source})")

    def get_context(self, key: str = None) -> dict | str:
        context = self._read(self._context)
        if key:
            entry = context.get(key, {})
            return entry.get("value", "") if isinstance(entry, dict) else ""
        return {k: v["value"] for k, v in context.items()
                if isinstance(v, dict) and "value" in v}

    def delete_context(self, key: str) -> None:
        context = self._read(self._context)
        if key in context:
            del context[key]
            self._write(self._context, context)

    # ── Stats & reset ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "alerts_stored":   len(self._read(self._alerts)),
            "agents_known":    len(self._read(self._agents)),
            "context_entries": len(self._read(self._context)),
            "data_dir":        str(self.data_dir),
        }

    def reset(self) -> None:
        self._write(self._alerts,  [])
        self._write(self._agents,  {})
        self._write(self._context, {})
        logger.info("[MEMORY] Memory reset.")
