# mcp-defense

`mcp-defense` is a small Python defense layer for AI agents that load tools
through MCP. It is designed to reduce the risk of Tool Poisoning: malicious
instructions hidden in tool descriptions or schemas that steer an agent into
calling unrelated tools, leaking data, or ignoring the user's intent.

The package is dependency-free by default. The optional LLM audit layer uses
Anthropic and must be enabled explicitly.

## Defense Layers

```text
Tool load   -> Layer 1: RegexScanner
Tool load   -> Layer 2: LLMAuditor (optional)
Tool call   -> Layer 3: ParameterGuard
Runtime     -> Layer 4: ReasoningMonitor
```

| Layer | When it runs | Purpose |
| --- | --- | --- |
| `RegexScanner` | Tool load | Blocks known poison patterns in descriptions and schemas. |
| `LLMAuditor` | Tool load | Optional semantic review for obfuscated payloads. |
| `ParameterGuard` | Every tool call | Enforces per-tool parameter policy. |
| `ReasoningMonitor` | Every tool call | Alerts on high-risk calls that do not match user intent. |

## Install

```bash
pip install mcp-defense
```

Optional LLM audit:

```bash
pip install "mcp-defense[llm]"
export ANTHROPIC_API_KEY="sk-ant-..."
```

## Quickstart

```python
from mcp_defense import ToolPoisonDefense

defense = ToolPoisonDefense()

safe_tools = defense.load_tools(mcp_client.list_tools())

result = defense.call_tool(
    session_id="session-1",
    tool_name=tool_name,
    params=params,
    user_request=user_message,
    executor=your_tool_executor,
)
```

Enable Layer 2 only when the optional dependency and API key are configured:

```python
defense = ToolPoisonDefense(use_llm_audit=True)
```

## Custom Rules

```python
from mcp_defense import ToolPoisonDefense
from mcp_defense.guard import ToolRules

defense = ToolPoisonDefense()

defense.register_tool_rules(
    "send_internal_report",
    ToolRules(
        field_patterns={"to": r"^[\w.]+@example\.com$"},
        blocked_fields=["bcc", "forward_to", "extra_recipients"],
        required_fields=["to", "subject"],
    ),
)

defense.register_high_risk_tool(
    "send_internal_report",
    ["send", "email", "report"],
)
```

## MCP SDK Pattern

For async MCP clients, use `acall_tool`:

```python
async def executor(name, arguments):
    return await session.call_tool(name, arguments)

result = await defense.acall_tool(
    session_id="session-1",
    tool_name=name,
    params=arguments,
    user_request=user_request,
    executor=executor,
)
```

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

## Security Notes

This package is a defense-in-depth layer, not a complete sandbox. In production,
combine it with least-privilege MCP servers, read-only credentials where
possible, network egress controls, tool allowlists, and auditable logs.

## License

MIT
