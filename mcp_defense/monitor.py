"""
Layer 4 - ReasoningMonitor.

Runtime anomaly detection for tool calls. This layer alerts but does not block;
blocking belongs in ParameterGuard so monitoring cannot break normal execution.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

DEFAULT_HIGH_RISK_TOOLS: set[str] = {
    "send_whatsapp_message",
    "send_email",
    "send_slack_message",
    "read_file",
    "write_file",
    "execute_sql",
    "http_request",
    "execute_code",
    "list_repositories",
    "create_pull_request",
}

DEFAULT_INTENT_KEYWORDS: dict[str, list[str]] = {
    "send_whatsapp_message": ["send", "message", "whatsapp", "text", "gửi", "nhắn"],
    "send_email": ["send", "email", "mail", "gửi", "thư"],
    "send_slack_message": ["send", "slack", "message", "channel", "gửi"],
    "read_file": ["read", "file", "open", "show", "view", "đọc", "xem"],
    "write_file": ["write", "file", "save", "create", "ghi", "lưu", "tạo"],
    "execute_sql": ["query", "database", "db", "sql", "truy vấn"],
    "http_request": ["fetch", "request", "api", "url", "http", "call", "gọi"],
    "execute_code": ["run", "execute", "code", "script", "chạy"],
    "list_repositories": ["repo", "repository", "github", "code", "dự án"],
    "create_pull_request": ["pr", "pull request", "merge", "push"],
}


@dataclass
class ToolCallEvent:
    session_id: str
    tool_name: str
    params: dict
    user_request: str
    timestamp: float = field(default_factory=time.time)
    flagged: bool = False
    flag_reason: Optional[str] = None
    flag_reasons: list[str] = field(default_factory=list)


@dataclass
class AlertEvent:
    level: str
    event_type: str
    message: str
    tool_event: ToolCallEvent


class ReasoningMonitor:
    """Correlates tool calls with user intent and alerts on anomalies."""

    def __init__(
        self,
        alert_callback: Optional[Callable[[AlertEvent], None]] = None,
        max_calls_per_session: int = 20,
        burst_window_seconds: float = 5.0,
        burst_threshold: int = 5,
    ):
        self.alert_callback = alert_callback or self._default_alert
        self.max_calls_per_session = max_calls_per_session
        self.burst_window_seconds = burst_window_seconds
        self.burst_threshold = burst_threshold
        self.high_risk_tools = set(DEFAULT_HIGH_RISK_TOOLS)
        self.intent_keywords = {k: list(v) for k, v in DEFAULT_INTENT_KEYWORDS.items()}
        self._events: list[ToolCallEvent] = []
        self._session_events: dict[str, list[ToolCallEvent]] = defaultdict(list)

    def register_high_risk_tool(self, tool_name: str, intent_keywords: list[str]) -> None:
        self.high_risk_tools.add(tool_name)
        self.intent_keywords[tool_name] = [kw.lower() for kw in intent_keywords]

    def record(
        self,
        session_id: str,
        tool_name: str,
        params: dict,
        user_request: str,
    ) -> ToolCallEvent:
        event = ToolCallEvent(session_id, tool_name, params, user_request)
        self._events.append(event)
        self._session_events[session_id].append(event)

        self._detect_unsolicited(event)
        self._detect_excessive(event)
        self._detect_burst(event)
        return event

    def export_session(self, session_id: str) -> list[dict]:
        return [
            {
                "timestamp": e.timestamp,
                "tool": e.tool_name,
                "params": e.params,
                "user_request": e.user_request,
                "flagged": e.flagged,
                "flag_reason": e.flag_reason,
                "flag_reasons": list(e.flag_reasons),
            }
            for e in self._session_events.get(session_id, [])
        ]

    def flagged_events(self, session_id: Optional[str] = None) -> list[ToolCallEvent]:
        events = self._session_events.get(session_id, []) if session_id else self._events
        return [e for e in events if e.flagged]

    def _detect_unsolicited(self, event: ToolCallEvent) -> None:
        if event.tool_name not in self.high_risk_tools:
            return

        keywords = self.intent_keywords.get(event.tool_name, [])
        request = event.user_request.lower()
        if keywords and any(keyword in request for keyword in keywords):
            return

        self._flag(
            event,
            level="WARNING",
            event_type="unsolicited_high_risk_tool",
            message=(
                f"High-risk tool '{event.tool_name}' called without matching user intent. "
                f"User said: \"{event.user_request[:120]}\""
            ),
        )

    def _detect_excessive(self, event: ToolCallEvent) -> None:
        count = len(self._session_events[event.session_id])
        if count == self.max_calls_per_session:
            self._flag(
                event,
                level="WARNING",
                event_type="excessive_tool_calls",
                message=f"Session '{event.session_id}' reached {count} tool calls.",
            )

    def _detect_burst(self, event: ToolCallEvent) -> None:
        now = event.timestamp
        window = [
            e for e in self._session_events[event.session_id]
            if now - e.timestamp <= self.burst_window_seconds
        ]
        if len(window) >= self.burst_threshold:
            self._flag(
                event,
                level="CRITICAL",
                event_type="rapid_burst",
                message=(
                    f"{len(window)} tool calls in {self.burst_window_seconds}s "
                    f"in session '{event.session_id}'."
                ),
            )

    def _flag(
        self,
        event: ToolCallEvent,
        level: str,
        event_type: str,
        message: str,
    ) -> None:
        event.flagged = True
        event.flag_reason = message
        event.flag_reasons.append(message)
        alert = AlertEvent(level, event_type, message, event)
        logger.warning(
            "[Monitor] %s event_type='%s' session='%s' tool='%s'",
            level,
            event_type,
            event.session_id,
            event.tool_name,
            extra={"event": event_type, "session": event.session_id},
        )
        try:
            self.alert_callback(alert)
        except Exception:
            logger.exception("[Monitor] alert callback failed")

    @staticmethod
    def _default_alert(alert: AlertEvent) -> None:
        logger.warning("[Defense alert] %s: %s", alert.level, alert.message)
