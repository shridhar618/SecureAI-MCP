"""SecureAI as an MCP server: read-mostly governance tools for MCP clients.

Runs in its own process (``python -m app.mcp_server``), never inside the
eventlet web process. See docs/MCP_SERVER.md.
"""
