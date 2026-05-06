"""
Layer 1 - RegexScanner.

Fast load-time scanning for known tool-poisoning indicators in MCP tool
metadata. The scanner checks the description plus schema-like fields because
poison payloads are often hidden in parameter descriptions.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


DEFAULT_PATTERNS: list[tuple[str, str]] = [
    (
        r"(?i)\b(do\s+not|don't|never|khong|không)\b.{0,40}"
        r"\b(tell|show|mention|inform|display|reveal|notify|noi|nói)\b",
        "secrecy_demand",
    ),
    (
        r"(?i)\b(secretly|silently|without\s+(the\s+)?user\s+(knowing|noticing)|"
        r"ẩn\s+danh|bí\s+mật)\b",
        "stealth_instruction",
    ),
    (
        r"(?i)\b(before|prior\s+to|first|trước\s+khi)\b.{0,80}"
        r"\b(call|invoke|trigger|send|read|execute|run|gọi|gửi|đọc|chạy)\b",
        "pre_action_injection",
    ),
    (
        r"(?i)\[(SYSTEM|INTERNAL|IMPORTANT\s+SYSTEM|HIDDEN|COMPLIANCE|ADMIN|"
        r"MANDATORY|DEVELOPER|ROOT)\]",
        "fake_system_marker",
    ),
    (
        r"(?i)\b(ignore|override|bypass|disregard)\b.{0,40}"
        r"\b(previous|user|system|developer|safety|policy|instruction)s?\b",
        "instruction_override",
    ),
    (
        r"(?i)(~/\.|/etc/|/root/|C:\\Users|\.aws|id_rsa|\.ssh|"
        r"private.?key|credentials|api.?key|token|secret)",
        "credential_or_fs_access",
    ),
    (r"\+[0-9][0-9\s().-]{7,20}[0-9]", "suspicious_phone_number"),
    (
        r"(?i)\b(exfil|exfiltrate|leak|forward.{0,20}copy|blind.?carbon|bcc\b|"
        r"backup.{0,15}send|mirror.{0,15}to|webhook|pastebin)\b",
        "exfiltration_vocab",
    ),
    (
        r"(?i)\b(in\s+(this|every|each)\s+session|every\s+time\s+you|"
        r"whenever\s+you|for\s+all\s+future\s+requests)\b",
        "session_scope_override",
    ),
    (
        r"(?i)\b(invoke|execute|call|run|trigger)\s+`?[a-z][a-z0-9_:-]{2,80}`?"
        r"\s*\(",
        "cross_tool_invocation",
    ),
]

SCANNED_KEYS = {
    "name",
    "description",
    "inputSchema",
    "input_schema",
    "parameters",
    "schema",
}


@dataclass
class ScanResult:
    passed: bool
    tool_name: str
    matched_pattern: Optional[str] = None
    matched_label: Optional[str] = None
    context_snippet: Optional[str] = None


class RegexScanner:
    """Scans MCP tool definitions for known poison patterns."""

    def __init__(
        self,
        extra_patterns: Optional[list[tuple[str, str]]] = None,
        skip_default: bool = False,
    ):
        self._patterns: list[tuple[re.Pattern, str]] = []
        for pattern, label in extra_patterns or []:
            self.add_pattern(pattern, label)
        if not skip_default:
            for pattern, label in DEFAULT_PATTERNS:
                self._patterns.append((re.compile(pattern), label))

    def add_pattern(self, pattern: str, label: str) -> None:
        self._patterns.append((re.compile(pattern), label))

    def scan_tool(self, tool: dict) -> ScanResult:
        name = str(_tool_get(tool, "name", "unknown"))
        text = _tool_text(tool)

        for compiled, label in self._patterns:
            match = compiled.search(text)
            if not match:
                continue

            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            snippet = text[start:end].strip()
            logger.warning(
                "[Scanner] BLOCKED tool='%s' pattern='%s' snippet='%s'",
                name,
                label,
                snippet,
                extra={"tool": name, "pattern": label, "event": "scan_blocked"},
            )
            return ScanResult(
                passed=False,
                tool_name=name,
                matched_pattern=compiled.pattern,
                matched_label=label,
                context_snippet=snippet,
            )

        logger.debug("[Scanner] PASSED tool='%s'", name)
        return ScanResult(passed=True, tool_name=name)

    def filter(self, tools: list[dict]) -> tuple[list[dict], list[ScanResult]]:
        safe: list[dict] = []
        blocked: list[ScanResult] = []
        for tool in tools:
            result = self.scan_tool(tool)
            if result.passed:
                safe.append(tool)
            else:
                blocked.append(result)

        if blocked:
            logger.error(
                "[Scanner] Blocked %d/%d tools: %s",
                len(blocked),
                len(tools),
                [r.tool_name for r in blocked],
            )
        return safe, blocked


def _tool_get(tool: Any, key: str, default: Any = None) -> Any:
    if isinstance(tool, dict):
        return tool.get(key, default)
    if hasattr(tool, "model_dump"):
        return tool.model_dump().get(key, default)
    return getattr(tool, key, default)


def _tool_text(tool: Any) -> str:
    if hasattr(tool, "model_dump"):
        tool = tool.model_dump()
    if not isinstance(tool, dict):
        return str(tool)

    selected = {k: v for k, v in tool.items() if k in SCANNED_KEYS}
    try:
        return json.dumps(selected, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(selected)
