"""
example_sandbox_invocation.py
=============================

This is an EXAMPLE of what the TrueForge agent generates at runtime inside
the Daytona sandbox via Code Mode.  The agent writes this script (or
something like it) dynamically based on the MCP tool outputs it collected.

In Code Mode, the sandbox has access to `mcp_client.call_tool()` which
bridges MCP tool calls back through the harness — credentials never enter
the sandbox.

The agent's SKILL.md instructs it to:
1. Call get_threat_events and get_honeypot_hits via MCP
2. Write a Python script in the sandbox that feeds those results into
   correlate() and prints the JSON verdict
3. The harness captures stdout and returns it to the agent

This file is NOT executed pre-baked — it is a reference template.
The agent generates a script LIKE this each run, with the actual data
embedded.  That's what makes it "generated code executed in a sandbox."
"""

import asyncio
import json
import sys

# In TrueForge's sandbox, mcp_client is available for bridged MCP calls
# from mcp_client import call_tool

# For standalone testing, we import correlate directly
sys.path.insert(0, ".")
from correlate import correlate


async def main():
    # ── In production, the agent would call MCP tools via the bridge: ─────
    #
    # threat_data = await call_tool(
    #     "verdict-mcp",
    #     "get_threat_events",
    #     body={"ip": "185.220.101.42"},
    # )
    # honeypot_data = await call_tool(
    #     "verdict-mcp",
    #     "get_honeypot_hits",
    #     body={"ip": "185.220.101.42"},
    # )
    #
    # Optionally, Tier 2:
    # try:
    #     history = await call_tool(
    #         "verdict-mcp",
    #         "investigate_history",
    #         body={"query": "What do we know about IP 185.220.101.42?"},
    #     )
    #     historical_match = history.get("answer")
    # except Exception:
    #     historical_match = None  # Graceful degradation
    #
    # ── For this example, we use inline test data: ────────────────────────

    ip = "185.220.101.42"
    threat_events = [
        {
            "threat_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "matched_pattern": "sqli_union_select",
            "timestamp": "2026-08-26T11:00:01+00:00",
            "ai_analysis": "UNION-based SQL injection targeting user table",
        },
        {
            "threat_type": "SENSITIVE_DATA_LEAK",
            "severity": "CRITICAL",
            "matched_pattern": "api_key_leak",
            "timestamp": "2026-08-26T11:00:12+00:00",
            "ai_analysis": "Attempted exfiltration of API key via POST body",
        },
    ]
    honeypot_hits = [
        {
            "port": 2222,
            "service": "ssh",
            "timestamp": "2026-08-26T10:58:45+00:00",
        },
    ]
    historical_match = None

    # ── Run correlation ───────────────────────────────────────────────────

    verdict = correlate(
        ip=ip,
        threat_events=threat_events,
        honeypot_hits=honeypot_hits,
        historical_match=historical_match,
    )

    # Print JSON to stdout — the harness captures this
    print(json.dumps(verdict, indent=2))


asyncio.run(main())
