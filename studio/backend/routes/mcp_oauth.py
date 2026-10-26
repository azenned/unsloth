# SPDX-License-Identifier: AGPL-3.0-only
"""Public callback: the SDK-generated state is the one-use flow capability."""
import asyncio
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from core.inference.mcp_oauth import CALLBACK_PATH, flows, prune

router = APIRouter()


@router.get(CALLBACK_PATH, response_class = HTMLResponse)
async def oauth_callback(request: Request):
    headers = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'"}
    def page(message, status):
        return HTMLResponse(f"<!doctype html><title>MCP OAuth</title><p>{message}</p>", status_code = status, headers = headers)

    prune()
    states = request.query_params.getlist("state")
    if len(states) != 1 or not states[0]:
        return page("Invalid or expired OAuth state.", 400)
    for flow in list(flows.values()):
        if not flow.public or not flow.state or not flow.redirect_uri:
            continue
        if not secrets.compare_digest(states[0].encode(), flow.state.encode()):
            continue
        try:
            flow.complete(flow.redirect_uri + "?" + request.scope.get("query_string", b"").decode("ascii"))
        except (ValueError, KeyError, UnicodeError):
            return page("Invalid or expired OAuth callback.", 400)
        if flow.task:
            try:
                await asyncio.wait_for(asyncio.shield(flow.task), 15)
            except (TimeoutError, asyncio.CancelledError):
                return page("Authorization received. Check the connection in Unsloth Studio.", 202)
        if flow.result and flow.result.get("ok"):
            return page("MCP connected. You may close this window and return to Unsloth Studio.", 200)
        return page("OAuth authorization failed. Return to Unsloth Studio and retry.", 400)
    return page("Invalid or expired OAuth state.", 400)
