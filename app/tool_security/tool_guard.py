import json
from app.logger.audit_logger import log_event

# Minimal policy configuration
TOOL_POLICIES = {
    "execute_shell": {"blocked": True},
    "query_database": {"block_select_all": True},
    "refund_payment": {"max_amount": 100}
}

def extract_tool_calls(response_data: dict) -> list:
    """
    Extracts tool calls from an OpenAI-formatted response.
    Supports both 'tool_calls' list and legacy 'function_call'.
    """
    choices = response_data.get("choices", [])
    if not choices:
        return []
    
    message = choices[0].get("message", {})
    tool_calls = message.get("tool_calls", [])
    
    # Also support legacy function_call if present
    if not tool_calls and "function_call" in message:
        tool_calls = [message["function_call"]]
        
    return tool_calls

def validate_tool_call(tool_call: dict) -> tuple[bool, str]:
    """
    Validates a single tool call against security policies.
    Returns (is_valid, reason).
    """
    name = tool_call.get("name") or (tool_call.get("function", {}).get("name") if "function" in tool_call else None)
    if not name:
        return True, ""

    policy = TOOL_POLICIES.get(name)
    if not policy:
        return True, ""

    # 1. Blocked Tools
    if policy.get("blocked"):
        return False, f"Tool '{name}' is strictly blocked by policy"

    # 2. Argument Parsing for detailed validation
    args_raw = tool_call.get("arguments") or (tool_call.get("function", {}).get("arguments") if "function" in tool_call else "{}")
    try:
        if isinstance(args_raw, str):
            args = json.loads(args_raw)
        else:
            args = args_raw
    except:
        args = {}

    # 3. Database select all check
    if name == "query_database" and policy.get("block_select_all"):
        query = args.get("query", "").lower()
        if "select *" in query:
            return False, "Broad database queries (SELECT *) are prohibited"

    # 4. Amount limits
    if name == "refund_payment" and "max_amount" in policy:
        amount = args.get("amount", 0)
        if amount > policy["max_amount"]:
            return False, f"Refund amount {amount} exceeds limit of {policy['max_amount']}"

    return True, ""
