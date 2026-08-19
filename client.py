"""Tiny health / tool-list client for the HTTP server."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser(description="DirectAdmin MCP HTTP client")
    parser.add_argument("--server", "-s", default=os.getenv("MCP_URL", "http://127.0.0.1:8888"))
    parser.add_argument("--token", "-k", default=os.getenv("MCP_AUTH_TOKEN", ""))
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--tools", action="store_true")
    parser.add_argument("--info", "-i", action="store_true")
    args = parser.parse_args()

    path = "/health"
    if args.tools:
        path = "/mcp/tools"
    elif args.info:
        path = "/about"

    url = args.server.rstrip("/") + path
    headers = {"Accept": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            print(json.dumps(json.loads(body), indent=2))
            return 0
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8"), file=sys.stderr)
        return 1
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
