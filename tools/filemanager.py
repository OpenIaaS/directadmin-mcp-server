"""File manager — list, search, and mutating actions (all confirmed)."""

from __future__ import annotations

from typing import Any, Dict

from da import call_da_api, client
from mcp_instance import mcp
from security import validate_fs_path
from tools.common import format_response, guard_confirm, log_tool_call


@mcp.tool()
@log_tool_call
async def fm_list(path: str = "/") -> Dict[str, Any]:
    """List a directory.

    Args:
        path: Absolute path inside the account home.
    """
    path = validate_fs_path(path)
    data = await client.request("/api/filemanager/list", method="GET", params={"path": path})
    return format_response(data)


@mcp.tool()
@log_tool_call
async def fm_tree(path: str = "/") -> Dict[str, Any]:
    """Directory tree.

    Args:
        path: Starting path.
    """
    path = validate_fs_path(path)
    data = await client.request("/api/filemanager/tree", method="GET", params={"path": path})
    return format_response(data)


@mcp.tool()
@log_tool_call
async def fm_disk_usage(path: str = "/") -> Dict[str, Any]:
    """Disk usage for a path.

    Args:
        path: Path.
    """
    path = validate_fs_path(path)
    data = await client.request("/api/filemanager/disk-usage", method="GET", params={"path": path})
    return format_response(data)


@mcp.tool()
@log_tool_call
async def fm_search_files(query: str, path: str = "/") -> Dict[str, Any]:
    """Search file names.

    Args:
        query: Filename fragment.
        path: Root to search.
    """
    path = validate_fs_path(path)
    data = await client.request(
        "/api/filemanager/search-files", method="GET", params={"q": query, "path": path}
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def fm_search_text(query: str, path: str = "/") -> Dict[str, Any]:
    """Search file contents.

    Args:
        query: Text.
        path: Root to search.
    """
    path = validate_fs_path(path)
    data = await client.request(
        "/api/filemanager/search-text", method="GET", params={"q": query, "path": path}
    )
    return format_response(data)


@mcp.tool()
@log_tool_call
async def fm_mkdir(path: str, confirm: bool = False) -> Dict[str, Any]:
    """Create a directory.

    Args:
        path: New directory path.
        confirm: Required.
    """
    rejected = guard_confirm("fm_mkdir", confirm)
    if rejected:
        return rejected
    path = validate_fs_path(path)
    return format_response(
        await call_da_api("/api/filemanager-actions/mkdir", method="POST", data={"path": path})
    )


@mcp.tool()
@log_tool_call
async def fm_remove(paths: list, confirm: bool = False) -> Dict[str, Any]:
    """Move paths to trash (or delete, depending on panel settings).

    Args:
        paths: List of paths.
        confirm: Required.
    """
    rejected = guard_confirm("fm_remove", confirm)
    if rejected:
        return rejected
    cleaned = [validate_fs_path(item) for item in paths]
    return format_response(
        await call_da_api("/api/filemanager-actions/remove", method="POST", data={"paths": cleaned})
    )


@mcp.tool()
@log_tool_call
async def fm_move(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Move files.

    Args:
        payload: Source/destination body.
        confirm: Required.
    """
    rejected = guard_confirm("fm_move", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/filemanager-actions/move", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def fm_copy(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Copy files.

    Args:
        payload: Source/destination body.
        confirm: Required.
    """
    rejected = guard_confirm("fm_copy", confirm)
    if rejected:
        return rejected
    return format_response(await call_da_api("/api/filemanager-actions/copy", method="POST", data=payload))


@mcp.tool()
@log_tool_call
async def fm_chmod(payload: Dict[str, Any], confirm: bool = False) -> Dict[str, Any]:
    """Change permissions.

    Args:
        payload: Paths + mode.
        confirm: Required.
    """
    rejected = guard_confirm("fm_chmod", confirm)
    if rejected:
        return rejected
    return format_response(
        await call_da_api("/api/filemanager-actions/chmod", method="POST", data=payload)
    )


@mcp.tool()
@log_tool_call
async def fm_trash() -> Dict[str, Any]:
    """List trash."""
    return format_response(await call_da_api("/api/filemanager/trash"))
