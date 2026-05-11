"""
Catalog-level defenses for MCP tool lists.

This layer catches attacks that are visible only when tools are compared as a
catalog: duplicate tools, name shadowing, and rug pulls where a previously
approved tool changes its metadata after the first load.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CatalogFinding:
    tool_name: str
    finding_type: str
    message: str
    related_tool: Optional[str] = None


class ToolCatalogGuard:
    """Detects catalog-level tool attacks at load time."""

    def __init__(self):
        self._fingerprints: dict[str, str] = {}

    def inspect(self, tools: list[dict]) -> tuple[list[dict], list[CatalogFinding]]:
        safe: list[dict] = []
        findings: list[CatalogFinding] = []
        seen_names: dict[str, str] = {}
        seen_normalized: dict[str, str] = {}

        for tool in tools:
            name = str(_tool_get(tool, "name", "unknown"))
            normalized = _normalize_name(name)

            duplicate = seen_names.get(name)
            if duplicate is not None:
                findings.append(
                    CatalogFinding(
                        tool_name=name,
                        finding_type="duplicate_tool_name",
                        message=f"Duplicate tool name '{name}' in the same catalog.",
                        related_tool=duplicate,
                    )
                )
                continue
            seen_names[name] = name

            shadowed = seen_normalized.get(normalized)
            if shadowed is not None and shadowed != name:
                findings.append(
                    CatalogFinding(
                        tool_name=name,
                        finding_type="tool_shadowing",
                        message=(
                            f"Tool '{name}' normalizes to the same identity as "
                            f"'{shadowed}'."
                        ),
                        related_tool=shadowed,
                    )
                )
                continue
            seen_normalized[normalized] = name

            fingerprint = _fingerprint_tool(tool)
            previous = self._fingerprints.get(name)
            if previous is not None and previous != fingerprint:
                findings.append(
                    CatalogFinding(
                        tool_name=name,
                        finding_type="tool_rug_pull",
                        message=(
                            f"Tool '{name}' changed metadata after it was previously "
                            "approved."
                        ),
                    )
                )
                continue

            safe.append(tool)
            self._fingerprints[name] = fingerprint

        if findings:
            logger.error(
                "[Catalog] Blocked %d/%d tools: %s",
                len(findings),
                len(tools),
                [(f.tool_name, f.finding_type) for f in findings],
            )

        return safe, findings


def _tool_get(tool: Any, key: str, default: Any = None) -> Any:
    if isinstance(tool, dict):
        if key == "name" and "function" in tool and "name" in tool["function"]:
            return tool["function"]["name"]
        return tool.get(key, default)
    if hasattr(tool, "model_dump"):
        return tool.model_dump().get(key, default)
    return getattr(tool, key, default)


def _normalize_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _fingerprint_tool(tool: dict) -> str:
    if hasattr(tool, "model_dump"):
        tool = tool.model_dump()
    encoded = json.dumps(tool, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
