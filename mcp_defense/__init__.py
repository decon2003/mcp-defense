"""
mcp-defense - Tool Poisoning defense for AI agents using MCP.
"""

from .auditor import AuditResult, LLMAuditor
from .catalog import CatalogFinding, ToolCatalogGuard
from .chain import ChainPolicy, ChainViolation, ToolChainMonitor, ToolRiskProfile
from .defense import ToolPoisonDefense
from .guard import ParameterGuard, SecurityViolation, ToolRules
from .monitor import AlertEvent, ReasoningMonitor, ToolCallEvent
from .scanner import RegexScanner, ScanResult

__version__ = "1.0.0"

__all__ = [
    "ToolPoisonDefense",
    "ToolRiskProfile",
    "ToolCatalogGuard",
    "CatalogFinding",
    "ToolChainMonitor",
    "ChainPolicy",
    "ChainViolation",
    "RegexScanner",
    "ScanResult",
    "LLMAuditor",
    "AuditResult",
    "ParameterGuard",
    "SecurityViolation",
    "ToolRules",
    "ReasoningMonitor",
    "ToolCallEvent",
    "AlertEvent",
]
