"""
Tool attack-chain detection.

This module models tools as sources, sinks, transforms, or neutral steps and
detects risky chains such as `read_file -> http_request` inside one session.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class ChainViolation(Exception):
    """Raised when a tool call violates the configured chain policy."""

    def __init__(self, session_id: str, tool_name: str, reason: str):
        self.session_id = session_id
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"[Chain] {session_id}.{tool_name}: {reason}")


@dataclass(frozen=True)
class ToolRiskProfile:
    """
    Describes a tool's role in a possible attack chain.

    category:
        "source" for tools that read sensitive data.
        "sink" for tools that send data or mutate outside systems.
        "transform" for tools that process data.
        "neutral" for low-risk tools.
    """

    category: str = "neutral"
    data_types: tuple[str, ...] = ()
    external: bool = False
    intent_keywords: tuple[str, ...] = ()


@dataclass
class ChainPolicy:
    """
    Runtime policy for cross-tool chains.

    forbidden_edges blocks specific tool-to-tool transitions. source_to_sink
    blocks any source tool followed by an external sink in the same session.
    """

    source_to_sink: bool = True
    forbidden_edges: set[tuple[str, str]] = field(default_factory=set)
    window_seconds: Optional[float] = None


@dataclass
class ChainEvent:
    session_id: str
    tool_name: str
    profile: ToolRiskProfile
    params: dict
    user_request: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class ChainDecision:
    allowed: bool
    event_type: Optional[str] = None
    message: Optional[str] = None
    source_tool: Optional[str] = None
    sink_tool: Optional[str] = None


AlertCallback = Callable[[str, str, ChainDecision], None]


DEFAULT_TOOL_PROFILES: dict[str, ToolRiskProfile] = {
    "read_file": ToolRiskProfile("source", ("files",), False, ("read", "file", "open")),
    "write_file": ToolRiskProfile("sink", ("files",), False, ("write", "file", "save")),
    "execute_sql": ToolRiskProfile("source", ("database",), False, ("query", "database", "sql")),
    "http_request": ToolRiskProfile("sink", ("network",), True, ("fetch", "request", "api", "url")),
    "send_email": ToolRiskProfile("sink", ("messages",), True, ("send", "email", "mail")),
    "send_whatsapp_message": ToolRiskProfile(
        "sink", ("messages",), True, ("send", "message", "whatsapp")
    ),
    "send_slack_message": ToolRiskProfile("sink", ("messages",), True, ("send", "slack")),
    "execute_code": ToolRiskProfile("sink", ("code",), False, ("run", "execute", "code")),
    "list_repositories": ToolRiskProfile("source", ("code",), False, ("repo", "repository")),
    "create_pull_request": ToolRiskProfile("sink", ("code",), True, ("pr", "pull request")),
}


class ToolChainMonitor:
    """Tracks per-session tool sequences and detects attack-chain patterns."""

    def __init__(
        self,
        policy: Optional[ChainPolicy] = None,
        profiles: Optional[dict[str, ToolRiskProfile]] = None,
    ):
        self.policy = policy or ChainPolicy()
        self.profiles = dict(DEFAULT_TOOL_PROFILES)
        if profiles:
            self.profiles.update(profiles)
        self._session_events: dict[str, list[ChainEvent]] = defaultdict(list)
        self._decisions: dict[str, list[ChainDecision]] = defaultdict(list)

    def register_profile(self, tool_name: str, profile: ToolRiskProfile) -> None:
        self.profiles[tool_name] = profile

    def forbid_edge(self, source_tool: str, sink_tool: str) -> None:
        self.policy.forbidden_edges.add((source_tool, sink_tool))

    def check(
        self,
        session_id: str,
        tool_name: str,
        params: dict,
        user_request: str,
    ) -> ChainDecision:
        profile = self.profiles.get(tool_name, ToolRiskProfile())
        event = ChainEvent(session_id, tool_name, profile, params, user_request)
        history = self._recent_events(session_id, event.timestamp)

        decision = self._check_forbidden_edges(tool_name, history)
        if decision.allowed:
            decision = self._check_source_to_external_sink(event, history)

        self._session_events[session_id].append(event)
        self._decisions[session_id].append(decision)
        return decision

    def export_session(self, session_id: str) -> list[dict]:
        events = self._session_events.get(session_id, [])
        decisions = self._decisions.get(session_id, [])
        rows = []
        for event, decision in zip(events, decisions):
            rows.append(
                {
                    "timestamp": event.timestamp,
                    "tool": event.tool_name,
                    "category": event.profile.category,
                    "data_types": list(event.profile.data_types),
                    "external": event.profile.external,
                    "allowed": decision.allowed,
                    "event_type": decision.event_type,
                    "message": decision.message,
                    "source_tool": decision.source_tool,
                    "sink_tool": decision.sink_tool,
                }
            )
        return rows

    def _recent_events(self, session_id: str, now: float) -> list[ChainEvent]:
        events = self._session_events.get(session_id, [])
        if self.policy.window_seconds is None:
            return events
        return [event for event in events if now - event.timestamp <= self.policy.window_seconds]

    def _check_forbidden_edges(self, tool_name: str, history: list[ChainEvent]) -> ChainDecision:
        for previous in reversed(history):
            if (previous.tool_name, tool_name) in self.policy.forbidden_edges:
                return ChainDecision(
                    allowed=False,
                    event_type="forbidden_tool_edge",
                    message=f"Forbidden tool chain: {previous.tool_name} -> {tool_name}",
                    source_tool=previous.tool_name,
                    sink_tool=tool_name,
                )
        return ChainDecision(allowed=True)

    def _check_source_to_external_sink(
        self,
        event: ChainEvent,
        history: list[ChainEvent],
    ) -> ChainDecision:
        if not self.policy.source_to_sink:
            return ChainDecision(allowed=True)
        if event.profile.category != "sink" or not event.profile.external:
            return ChainDecision(allowed=True)

        for previous in reversed(history):
            if previous.profile.category != "source":
                continue
            overlap = set(previous.profile.data_types) & set(event.profile.data_types)
            if overlap or event.profile.external:
                return ChainDecision(
                    allowed=False,
                    event_type="source_to_external_sink",
                    message=(
                        f"Sensitive source-to-external-sink chain: "
                        f"{previous.tool_name} -> {event.tool_name}"
                    ),
                    source_tool=previous.tool_name,
                    sink_tool=event.tool_name,
                )
        return ChainDecision(allowed=True)
