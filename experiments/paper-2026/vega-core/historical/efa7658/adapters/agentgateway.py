#!/usr/bin/env python3
"""Agentgateway pin and capability declaration for reproducible preflight."""

AGENTGATEWAY_VERSION = "1.5.0"
AGENTGATEWAY_COMMIT = "fe6732474a96a0363dfb9822859af4e9bab360fa"
AGENTGATEWAY_LINUX_AMD64_SHA256 = "daca5cda76e8c5ab0c1a75912fecf2d6365095403f810db72029c49d14a37e7b"

# At this commit, request-time CEL can gate MCP tool identity. Decoded tool arguments
# are post-request attributes, so argument authorization is deliberately delegated to
# OPA before forwarding. Keeping this fact executable prevents an inflated claim.
REQUEST_TIME_FIELDS = frozenset({"mcp.tool.name", "mcp.tool.target", "jwt.sub"})
POST_REQUEST_ONLY_FIELDS = frozenset({"mcp.tool.arguments"})


def supports_request_argument_authorization() -> bool:
    return False
