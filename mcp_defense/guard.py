"""
Layer 3 - ParameterGuard.

Runtime validation for tool call parameters. It is intentionally conservative:
the defaults catch common exfiltration and privilege-escalation patterns, while
production users should add allowlists for their own high-risk tools.
"""

from __future__ import annotations

import logging
import ntpath
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class SecurityViolation(Exception):
    """Raised when ParameterGuard detects a policy violation."""

    def __init__(self, tool: str, field_name: str, reason: str):
        self.tool = tool
        self.field_name = field_name
        self.reason = reason
        super().__init__(f"[Guard] {tool}.{field_name}: {reason}")


@dataclass
class ToolRules:
    blocked_fields: list[str] = field(default_factory=list)
    field_patterns: dict[str, str] = field(default_factory=dict)
    allowed_prefixes: dict[str, list[str]] = field(default_factory=dict)
    blocked_keywords: dict[str, list[str]] = field(default_factory=dict)
    required_fields: list[str] = field(default_factory=list)
    allowed_domains: dict[str, list[str]] = field(default_factory=dict)
    blocked_domains: dict[str, list[str]] = field(default_factory=dict)
    _compiled: dict[str, re.Pattern] = field(default_factory=dict, repr=False)

    def _get_pattern(self, field_name: str) -> Optional[re.Pattern]:
        if field_name not in self._compiled and field_name in self.field_patterns:
            self._compiled[field_name] = re.compile(self.field_patterns[field_name])
        return self._compiled.get(field_name)


class ParameterGuard:
    """Runtime parameter validator."""

    DEFAULT_RULES: dict[str, ToolRules] = {
        "send_whatsapp_message": ToolRules(
            blocked_fields=["bcc", "cc", "extra_recipients", "forward_to"],
            field_patterns={"to": r"^\+?[0-9][0-9\s().-]{7,20}$"},
        ),
        "send_email": ToolRules(
            blocked_fields=["bcc", "forward_to", "extra_recipients"],
        ),
        "send_slack_message": ToolRules(
            blocked_fields=["bcc", "forward_to", "extra_recipients", "webhook_url"],
        ),
        "read_file": ToolRules(
            blocked_keywords={"path": ["../", "..\\", "/etc/", "/root/", "~", "%USERPROFILE%"]},
        ),
        "write_file": ToolRules(
            blocked_keywords={"path": ["../", "..\\", "/etc/", "/root/", "~", "%USERPROFILE%"]},
        ),
        "execute_sql": ToolRules(
            blocked_keywords={
                "query": [
                    "DROP ",
                    "DELETE ",
                    "TRUNCATE ",
                    "INSERT ",
                    "UPDATE ",
                    "ALTER ",
                    "CREATE ",
                    "GRANT ",
                    "REVOKE ",
                    "--",
                    "/*",
                    "xp_",
                ]
            },
        ),
        "http_request": ToolRules(
            blocked_keywords={"url": ["file://", "ftp://", "gopher://"]},
            blocked_domains={"url": ["localhost", "127.0.0.1", "0.0.0.0", "::1"]},
        ),
    }

    def __init__(self, use_defaults: bool = True):
        self._rules: dict[str, ToolRules] = {}
        if use_defaults:
            self._rules.update(self.DEFAULT_RULES)

    def register(self, tool_name: str, rules: ToolRules) -> None:
        self._rules[tool_name] = rules
        logger.debug("[Guard] Registered rules for tool='%s'", tool_name)

    def validate(self, tool_name: str, params: dict) -> dict:
        if not isinstance(params, dict):
            raise SecurityViolation(tool_name, "params", "params must be a dictionary")

        rules = self._rules.get(tool_name)
        if not rules:
            logger.debug("[Guard] No rules for tool='%s', passing through.", tool_name)
            return params

        flat = _flatten(params)

        for field_name in rules.required_fields:
            if _lookup(flat, field_name) is None:
                raise SecurityViolation(tool_name, field_name, "required field missing")

        for field_name in rules.blocked_fields:
            if _lookup(flat, field_name) is not None:
                raise SecurityViolation(tool_name, field_name, "field is not allowed")

        for field_name, pattern_text in rules.field_patterns.items():
            value = _lookup(flat, field_name)
            if value is None:
                continue
            pattern = rules._get_pattern(field_name)
            if pattern is None or not pattern.fullmatch(str(value)):
                raise SecurityViolation(
                    tool_name,
                    field_name,
                    f"value '{value}' does not match allowed pattern",
                )

        for field_name, prefixes in rules.allowed_prefixes.items():
            value = _lookup(flat, field_name)
            if value is None:
                continue
            value_text = _normalize_path(str(value)) if "path" in field_name.lower() else str(value)
            normalized_prefixes = [
                _normalize_path(prefix) if "path" in field_name.lower() else prefix
                for prefix in prefixes
            ]
            if not any(_within_prefix(value_text, prefix) for prefix in normalized_prefixes):
                raise SecurityViolation(
                    tool_name,
                    field_name,
                    f"value '{value}' is outside allowed prefixes {prefixes}",
                )

        for field_name, keywords in rules.blocked_keywords.items():
            value = _lookup(flat, field_name)
            if value is None:
                continue
            value_text = _normalize_path(str(value)) if "path" in field_name.lower() else str(value)
            haystack = value_text.upper()
            for keyword in keywords:
                if keyword.upper() in haystack:
                    raise SecurityViolation(
                        tool_name,
                        field_name,
                        f"value contains blocked keyword '{keyword}'",
                    )

        for field_name, domains in rules.allowed_domains.items():
            value = _lookup(flat, field_name)
            if value is not None and not _domain_allowed(str(value), domains):
                raise SecurityViolation(tool_name, field_name, "URL domain is not allowed")

        for field_name, domains in rules.blocked_domains.items():
            value = _lookup(flat, field_name)
            if value is not None and _domain_blocked(str(value), domains):
                raise SecurityViolation(tool_name, field_name, "URL domain is blocked")

        logger.debug("[Guard] PASSED tool='%s'", tool_name)
        return params


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            key_text = str(key)
            full_key = f"{prefix}.{key_text}" if prefix else key_text
            out.update(_flatten(child, full_key))
        return out
    return {prefix: value}


def _lookup(flat: dict[str, Any], field_name: str) -> Any:
    if field_name in flat:
        return flat[field_name]
    suffix = f".{field_name}"
    for key, value in flat.items():
        if key.endswith(suffix):
            return value
    return None


def _normalize_path(path: str) -> str:
    path = path.replace("\\", "/")
    if re.match(r"^[A-Za-z]:/", path):
        return ntpath.normpath(path).replace("\\", "/")
    return posixpath.normpath(path)


def _within_prefix(value: str, prefix: str) -> bool:
    value = value.rstrip("/")
    prefix = prefix.rstrip("/")
    return value == prefix or value.startswith(prefix + "/")


def _hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip("[]")


def _domain_allowed(url: str, allowed: list[str]) -> bool:
    host = _hostname(url)
    return bool(host) and any(host == d.lower() or host.endswith("." + d.lower()) for d in allowed)


def _domain_blocked(url: str, blocked: list[str]) -> bool:
    host = _hostname(url)
    return bool(host) and any(host == d.lower() or host.endswith("." + d.lower()) for d in blocked)
