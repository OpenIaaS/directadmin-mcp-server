"""stdio MCP entrypoint — use this from Claude Desktop / Cursor / Codex."""

from __future__ import annotations

import logging
import os
import sys

from config import settings, setup_logging
from mcp_instance import mcp

logger = logging.getLogger(__name__)


def main() -> None:
    setup_logging()
    os.makedirs("logs", exist_ok=True)
    logger.info("stdio MCP starting (python=%s)", sys.version.split()[0])
    logger.info("config=%s", settings.public_dict())
    import tools

    loaded = tools.load_all_tools()
    logger.info("Loaded %d tool modules: %s", len(loaded), ", ".join(loaded))
    mcp.run(transport="stdio")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
