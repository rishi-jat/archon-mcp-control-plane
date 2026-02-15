"""End-to-end MCP protocol test.

Spawns each ARCHON MCP server over stdio, connects as a client,
lists tools, and invokes a tool against a real GitHub repo.
"""

import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PYTHON = sys.executable
BASE = "/Users/rishijat/Documents/Project_archestra/mcp-servers"


async def test_server(name: str, cwd: str, tool_name: str, tool_args: dict):
    """Spawn a server, list tools, call one tool, print result."""
    params = StdioServerParameters(
        command=PYTHON,
        args=["server.py"],
        cwd=cwd,
    )

    print(f"\n{'='*60}")
    print(f"  Testing: {name}")
    print(f"{'='*60}")

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"  Tools: {tool_names}")

            print(f"  Calling: {tool_name}({tool_args})")
            result = await session.call_tool(tool_name, arguments=tool_args)
            data = json.loads(result.content[0].text)

            # Print a summary based on server type
            if "health_score" in data:
                print(f"  Result: Health {data['health_score']}/100 (Grade: {data['grade']})")
                print(f"  Recommendations: {data.get('recommendations', [])}")
            elif "aggregate_risk_level" in data:
                print(f"  Result: Risk Level = {data['aggregate_risk_level']}")
                print(f"  Commits Analyzed: {data.get('commits_analyzed', 'N/A')}")
            elif "action_type" in data:
                print(f"  Result: Action logged — {data['action_type']}")
                print(f"  Status: {data['status']}")
            else:
                # Generic: print first few keys
                for k in list(data.keys())[:5]:
                    print(f"  {k}: {data[k]}")

    print(f"  PASSED ✓")


async def main():
    print("ARCHON End-to-End MCP Protocol Test")
    print("=" * 60)

    # Test 1: repo-intel — get_repository_health
    await test_server(
        name="archon-repo-intel",
        cwd=f"{BASE}/repo-intel",
        tool_name="get_repository_health",
        tool_args={"owner": "expressjs", "repo": "express"},
    )

    # Test 2: repo-intel — analyze_recent_commits
    await test_server(
        name="archon-repo-intel (commits)",
        cwd=f"{BASE}/repo-intel",
        tool_name="analyze_recent_commits",
        tool_args={"owner": "expressjs", "repo": "express", "count": 3},
    )

    # Test 3: actions — log_action
    await test_server(
        name="archon-actions",
        cwd=f"{BASE}/actions",
        tool_name="log_action",
        tool_args={
            "action_type": "test_run",
            "repository": "archon/test",
            "detail": "End-to-end MCP protocol test",
            "severity": "info",
        },
    )

    print(f"\n{'='*60}")
    print("  All tests passed ✓")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
