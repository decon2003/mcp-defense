"""
ToolPoisonDefense - 4-layer defense facade.

This is the main integration point:

    defense = ToolPoisonDefense()
    safe_tools = defense.load_tools(raw_tools)
    result = defense.call_tool(session_id, tool_name, params, user_request, executor)
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Optional

from .auditor import AuditResult, LLMAuditor
from .catalog import CatalogFinding, ToolCatalogGuard
from .chain import ChainPolicy, ToolChainMonitor, ToolRiskProfile
from .guard import ParameterGuard, SecurityViolation, ToolRules
from .monitor import AlertEvent, ReasoningMonitor
from .scanner import RegexScanner, ScanResult

logger = logging.getLogger(__name__)


class ToolPoisonDefense:
    """
    Orchestrates the four defense layers.

    Layer 1: RegexScanner at tool load time.
    Layer 2: LLMAuditor at tool load time, opt-in because it needs an API key.
    Layer 3: ParameterGuard at tool call time.
    Layer 4: ReasoningMonitor at tool call time.
    """

    def __init__(
        self,
        scanner: Optional[RegexScanner] = None,
        auditor: Optional[LLMAuditor] = None,
        catalog_guard: Optional[ToolCatalogGuard] = None,
        guard: Optional[ParameterGuard] = None,
        chain_monitor: Optional[ToolChainMonitor] = None,
        chain_policy: Optional[ChainPolicy] = None,
        alert_callback: Optional[Callable[[AlertEvent], None]] = None,
        use_llm_audit: bool = False,
        block_attack_chains: bool = False,
        auto_classify: bool = True,
    ):
        self.scanner = scanner or RegexScanner()
        self.auditor = auditor or LLMAuditor()
        self.catalog_guard = catalog_guard or ToolCatalogGuard()
        self.guard = guard or ParameterGuard()
        self.monitor = ReasoningMonitor(alert_callback=alert_callback)
        self.chain_monitor = chain_monitor or ToolChainMonitor(policy=chain_policy)
        self._use_llm = use_llm_audit
        self.block_attack_chains = block_attack_chains
        self.auto_classify = auto_classify

        self.last_scan_blocked: list[ScanResult] = []
        self.last_audit_blocked: list[AuditResult] = []
        self.last_catalog_blocked: list[CatalogFinding] = []

    def _auto_classify_tool(self, tool_name: str, description: str) -> None:
        """Automatically registers a risk profile if not already present."""
        if tool_name in self.chain_monitor.profiles:
            return

        name = tool_name.lower()
        desc = description.lower()
        category = "neutral"
        external = False

        # Sources (Reading data)
        if any(w in name or w in desc for w in ["read", "get", "list", "fetch", "access", "file", "note", "contact", "db", "query"]):
            category = "source"
        
        # Sinks (Sending data/Mutation)
        if any(w in name or w in desc for w in ["send", "write", "post", "upload", "execute", "request", "notify", "call", "push"]):
            category = "sink"
            # External sinks
            if any(w in name or w in desc for w in ["http", "url", "api", "external", "email", "mail", "slack", "webhook", "cloud"]):
                external = True
        
        if category != "neutral":
            self.register_tool_profile(tool_name, ToolRiskProfile(category=category, external=external))
            logger.info("[Defense] Auto-classified tool '%s' as %s (external=%s)", tool_name, category, external)

    def load_tools(self, raw_tools: list[dict]) -> list[dict]:
        """
        Run load-time defenses and return only tools approved for agent context.
        Automatically detects common formats (OpenAI, Anthropic, MCP).
        """
        # Format detection and auto-classification
        processed_tools = []
        for tool in raw_tools:
            # Handle OpenAI/Anthropic format vs raw MCP
            tool_name = tool.get("name")
            description = tool.get("description", "")
            
            if "function" in tool: # OpenAI Format
                tool_name = tool["function"]["name"]
                description = tool["function"].get("description", "")
            
            if self.auto_classify and tool_name:
                self._auto_classify_tool(tool_name, description)
            
            processed_tools.append(tool)

        after_catalog, catalog_blocked = self.catalog_guard.inspect(processed_tools)
        after_scan, scan_blocked = self.scanner.filter(after_catalog)

        blocked_by_llm: list[AuditResult] = []
        if self._use_llm and after_scan:
            after_audit, blocked_by_llm = self.auditor.filter(after_scan)
        else:
            after_audit = after_scan

        self.last_scan_blocked = scan_blocked
        self.last_audit_blocked = blocked_by_llm
        self.last_catalog_blocked = catalog_blocked

        logger.info(
            "[Defense] load_tools: %d/%d passed (%d catalog, %d scanner, %d auditor)",
            len(after_audit),
            len(raw_tools),
            len(catalog_blocked),
            len(scan_blocked),
            len(blocked_by_llm),
        )
        return after_audit

    def call_tool(
        self,
        session_id: str,
        tool_name: str,
        params: dict,
        user_request: str,
        executor: Callable[[str, dict], Any],
    ) -> Any:
        """
        Run call-time defenses and execute a synchronous tool executor if allowed.
        """
        try:
            validated = self.guard.validate(tool_name, params)
        except SecurityViolation as exc:
            logger.error("[Defense] call_tool blocked: %s", exc)
            self.monitor.record(session_id, tool_name, params, user_request)
            return {"error": "Tool call was rejected for security reasons."}

        chain_decision = self.chain_monitor.check(session_id, tool_name, validated, user_request)
        if not chain_decision.allowed:
            logger.warning("[Defense] attack chain detected: %s", chain_decision.message)
            event = self.monitor.record(session_id, tool_name, validated, user_request)
            self.monitor.flag_event(
                event,
                level="CRITICAL",
                event_type=chain_decision.event_type or "tool_attack_chain",
                message=chain_decision.message or "Tool attack chain detected.",
            )
            if self.block_attack_chains:
                return {"error": "Tool call was rejected because it matched a tool attack chain."}
            return executor(tool_name, validated)

        self.monitor.record(session_id, tool_name, validated, user_request)
        return executor(tool_name, validated)

    async def acall_tool(
        self,
        session_id: str,
        tool_name: str,
        params: dict,
        user_request: str,
        executor: Callable[[str, dict], Awaitable[Any]],
    ) -> Any:
        """
        Async variant for MCP SDK clients and other async executors.
        """
        try:
            validated = self.guard.validate(tool_name, params)
        except SecurityViolation as exc:
            logger.error("[Defense] acall_tool blocked: %s", exc)
            self.monitor.record(session_id, tool_name, params, user_request)
            return {"error": "Tool call was rejected for security reasons."}

        chain_decision = self.chain_monitor.check(session_id, tool_name, validated, user_request)
        if not chain_decision.allowed:
            logger.warning("[Defense] attack chain detected: %s", chain_decision.message)
            event = self.monitor.record(session_id, tool_name, validated, user_request)
            self.monitor.flag_event(
                event,
                level="CRITICAL",
                event_type=chain_decision.event_type or "tool_attack_chain",
                message=chain_decision.message or "Tool attack chain detected.",
            )
            if self.block_attack_chains:
                return {"error": "Tool call was rejected because it matched a tool attack chain."}
            return await executor(tool_name, validated)

        self.monitor.record(session_id, tool_name, validated, user_request)
        return await executor(tool_name, validated)

    def register_tool_rules(self, tool_name: str, rules: ToolRules) -> None:
        """Register custom parameter rules for a tool."""
        self.guard.register(tool_name, rules)

    def register_high_risk_tool(self, tool_name: str, intent_keywords: list[str]) -> None:
        """Register a custom high-risk tool for runtime intent monitoring."""
        self.monitor.register_high_risk_tool(tool_name, intent_keywords)

    def register_tool_profile(self, tool_name: str, profile: ToolRiskProfile) -> None:
        """Register a tool's role in attack-chain detection."""
        self.chain_monitor.register_profile(tool_name, profile)
        if profile.category in {"source", "sink"} or profile.intent_keywords:
            self.monitor.register_high_risk_tool(tool_name, list(profile.intent_keywords))

    def forbid_tool_chain(self, source_tool: str, sink_tool: str) -> None:
        """Block or flag a specific tool transition inside one session."""
        self.chain_monitor.forbid_edge(source_tool, sink_tool)

    def get_session_log(self, session_id: str) -> list[dict]:
        """Return the recorded event log for a session."""
        return self.monitor.export_session(session_id)

    def get_chain_log(self, session_id: str) -> list[dict]:
        """Return the tool-chain timeline for a session."""
        return self.chain_monitor.export_session(session_id)
