"""Shared FastMCP instance."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import FastMCP

from config import settings

logger = logging.getLogger(__name__)

mcp = FastMCP(
    settings.MCP_NAME,
    instructions=(
        "You are connected to a DirectAdmin control panel as an administrator. "
        "Prefer the curated tools (ssl_*, csf_*, bfm_*, users_*, system_*). "
        "Use da_list_endpoints / da_describe_endpoint / da_api for anything else "
        "in the New JSON API. Destructive tools require confirm=true. "
        "Never print login keys, passwords, or private keys back to the user."
    ),
)

logger.info("MCP instance '%s' created", settings.MCP_NAME)
