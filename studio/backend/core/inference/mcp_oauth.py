# SPDX-License-Identifier: AGPL-3.0-only
"""Browser handoff for MCP OAuth; FastMCP retains discovery, PKCE and token storage."""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

CALLBACK_PATH = "/api/mcp/oauth/callback"


def _callback_from_origin(value):
    parsed = urlsplit(value)
    if (value != value.strip() or any(ord(c) < 33 for c in value)
        or parsed.scheme != "https" or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
        or "?" in value or "#" in value or "\\" in value or "%" in parsed.netloc):
        raise ValueError("UNSLOTH_STUDIO_PUBLIC_URL must be an HTTPS origin")
    try:
        parsed.port
    except ValueError:
        raise ValueError("Invalid public URL port") from None
    from pydantic import AnyHttpUrl
    AnyHttpUrl(value)
    return value.rstrip("/") + CALLBACK_PATH


_request_callback: ContextVar = ContextVar("mcp_oauth_request_callback", default = None)


def public_callback_url():
    callback = _request_callback.get()
    if callback is not None:
        return callback
    value = os.environ.get("UNSLOTH_STUDIO_PUBLIC_URL")
    return _callback_from_origin(value) if value is not None else None


def proxy_callback_url(scope):
    from starlette.datastructures import Headers
    from utils.client_ip import trust_forwarded_headers

    if not trust_forwarded_headers():
        return None
    headers = Headers(scope = scope)
    proto = headers.getlist("x-forwarded-proto")
    if proto != ["https"]:
        return None
    hosts = headers.getlist("x-forwarded-host") or headers.getlist("host")
    if len(hosts) != 1 or "," in hosts[0] or not hosts[0]:
        return None
    try:
        return _callback_from_origin("https://" + hosts[0])
    except ValueError:
        return None


class OAuthCallbackOriginMiddleware:
    """Carry the request origin into SDK calls and background OAuth tasks."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        token = _request_callback.set(proxy_callback_url(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            _request_callback.reset(token)


active_flow: ContextVar = ContextVar("mcp_oauth_flow", default = None)


@dataclass
class OAuthFlow:
    account: str
    subject: str
    id: str = field(default_factory = lambda: secrets.token_urlsafe(32))
    created: float = field(default_factory = time.monotonic)
    authorization_url: str | None = None
    redirect_uri: str | None = None
    state: str | None = None
    issuer: str | None = None
    issuer_required: bool = False
    public: bool = False
    result: dict | None = None
    callback: asyncio.Future | None = None
    task: asyncio.Task | None = None

    def snapshot(self):
        return {"id": self.id, "authorization_url": self.authorization_url, "result": self.result}

    async def redirect(self, url):
        query = parse_qs(urlsplit(url).query)
        self.redirect_uri = query["redirect_uri"][0]
        self.state = query["state"][0]
        self.authorization_url = url
        self.callback = asyncio.get_running_loop().create_future()

    def complete(self, callback_url):
        if not self.authorization_url or not self.callback or self.callback.done() or self.result:
            raise ValueError("OAuth flow is not waiting for a callback")
        if time.monotonic() - self.created > 300:
            raise ValueError("OAuth flow expired")
        expected = urlsplit(self.redirect_uri)
        parsed = urlsplit(callback_url)
        if (parsed.scheme, parsed.netloc, parsed.path) != (expected.scheme, expected.netloc, expected.path) or parsed.fragment:
            raise ValueError("Paste the complete OAuth callback URL")
        query = parse_qs(parsed.query, keep_blank_values = True)
        if any(len(query.get(key, [])) > 1 for key in ("state", "code", "iss", "error", "error_description")):
            raise ValueError("Duplicate OAuth callback parameter")
        state = query.get("state", [])
        if len(state) != 1 or not secrets.compare_digest(state[0].encode(), (self.state or "").encode()):
            raise ValueError("OAuth state does not match")
        issuer = query.get("iss", [None])[0]
        from mcp.client.auth.utils import issuers_match
        if (issuer is not None and (self.issuer is None or not issuers_match(issuer, self.issuer))) or (self.issuer_required and issuer is None):
            raise ValueError("OAuth issuer does not match")
        if "error" in query:
            if "code" in query:
                raise ValueError("Ambiguous OAuth callback")
            self.callback.set_exception(ValueError("OAuth authorization was denied"))
            return
        code = query.get("code", [])
        if len(code) != 1 or not code[0]:
            raise ValueError("OAuth callback does not contain an authorization code")
        self.callback.set_result((code[0], state[0]))

    async def receive(self, local_callback):
        if self.public:
            try:
                return await asyncio.wait_for(self.callback, 300)
            finally:
                if not self.callback.done():
                    self.callback.cancel()
        local = asyncio.create_task(local_callback())
        try:
            done, _ = await asyncio.wait([local, self.callback], timeout = 300, return_when = asyncio.FIRST_COMPLETED)
            if self.callback in done:
                return self.callback.result()
            if local in done:
                return local.result()
            raise TimeoutError("OAuth callback timed out")
        finally:
            local.cancel()
            await asyncio.gather(local, return_exceptions = True)
            if self.callback and not self.callback.done():
                self.callback.cancel()


flows: dict[str, OAuthFlow] = {}


def prune():
    for key, flow in list(flows.items()):
        if time.monotonic() - flow.created > 600:
            if flow.task and not flow.task.done():
                flow.task.cancel()
            del flows[key]


class _OAuthLogFilter(logging.Filter):
    def filter(self, record):
        # The SDK logs exception tracebacks containing provider response bodies.
        record.msg = "MCP OAuth protocol event" if record.levelno < logging.ERROR else "MCP OAuth protocol failed"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        return True


def encrypted_token_storage(server_key):
    from mcp.client.auth import TokenStorage
    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
    from storage import credential_secrets
    from utils.account_context import current_account_id

    scope = hashlib.sha256((current_account_id() + "\0" + server_key).encode()).hexdigest()

    class EncryptedStorage(TokenStorage):
        def read(self, kind):
            return credential_secrets.get_secret("mcp_oauth_" + kind, scope)

        def write(self, kind, value):
            credential_secrets.upsert_secret("mcp_oauth_" + kind, scope, value)

        async def get_tokens(self):
            raw = self.read("tokens")
            return OAuthToken.model_validate_json(raw) if raw else None

        async def set_tokens(self, tokens):
            self.write("tokens", tokens.model_dump_json())
            self.write("expiry", json.dumps(time.time() + tokens.expires_in if tokens.expires_in is not None else None))

        async def get_token_expiry(self):
            raw = self.read("expiry")
            return json.loads(raw) if raw else None

        def client_info(self):
            raw = self.read("client")
            info = OAuthClientInformationFull.model_validate_json(raw) if raw else None
            if info and info.client_secret_expires_at and info.client_secret_expires_at <= time.time():
                return None
            return info

        async def get_client_info(self):
            return self.client_info()

        async def set_client_info(self, info):
            self.write("client", info.model_dump_json())

        async def clear(self):
            for kind in ("tokens", "expiry", "client"):
                credential_secrets.delete_secret("mcp_oauth_" + kind, scope)

    return EncryptedStorage()


def public_oauth_storage_key(url, callback):
    return url.rstrip("/") + "#studio-public-" + hashlib.sha256(callback.encode()).hexdigest()


def oauth_registration_status(url):
    """Expose the persisted registration identity, never the registered secret."""
    callback = public_callback_url()
    if callback is None:
        return {}
    info = encrypted_token_storage(public_oauth_storage_key(url, callback)).client_info()
    if info is None:
        return {}
    return {
        "oauth_registered_client_id": info.client_id,
        "has_oauth_registered_client_secret": bool(info.client_secret),
    }


def public_oauth_class():
    # Keep FastMCP's expiry/static-client initialization, but replace only its
    # loopback binding using the SDK's public constructor and FastMCP adapter.
    from fastmcp.client.auth import OAuth
    from mcp.client.auth import OAuthClientProvider
    from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata
    sdk_logger = logging.getLogger("mcp.client.auth.oauth2")
    if not any(isinstance(f, _OAuthLogFilter) for f in sdk_logger.filters):
        sdk_logger.addFilter(_OAuthLogFilter())

    class WebClientMetadata(OAuthClientMetadata):
        application_type: str = "web"

    class PublicOAuth(OAuth):
        def _bind(self, mcp_url):
            if self._bound:
                return
            callback = public_callback_url()
            metadata = WebClientMetadata(
                client_name = "Unsloth Studio", redirect_uris = [callback],
                grant_types = ["authorization_code", "refresh_token"],
                response_types = ["code"], application_type = "web",
                token_endpoint_auth_method = "client_secret_post" if self._client_secret else "none",
            )
            # Do not reuse loopback DCR registrations after switching callback origins.
            key = public_oauth_storage_key(mcp_url, callback)
            self.token_storage_adapter = encrypted_token_storage(key)
            self.mcp_url = mcp_url.rstrip("/")
            if self._client_id:
                self._static_client_info = OAuthClientInformationFull(
                    client_id = self._client_id, client_secret = self._client_secret,
                    **metadata.model_dump(exclude_none = True),
                )
            OAuthClientProvider.__init__(
                self, server_url = self.mcp_url, client_metadata = metadata,
                storage = self.token_storage_adapter, redirect_handler = self.redirect_handler,
                callback_handler = self.callback_handler, timeout = 300,
            )
            self._bound = True

        async def redirect_handler(self, authorization_url):
            flow = active_flow.get()
            if flow is None:
                raise ValueError("OAuth sign-in required: use Test connection in MCP Servers")
            flow.public = True
            metadata = self.context.oauth_metadata
            flow.issuer = str(metadata.issuer) if metadata else None
            flow.issuer_required = bool(getattr(metadata, "authorization_response_iss_parameter_supported", False))
            self.studio_flow = flow
            await flow.redirect(authorization_url)

        async def callback_handler(self):
            return await self.studio_flow.receive(None)

    return PublicOAuth


def browser_oauth_class():
    from fastmcp.client.auth import OAuth

    class BrowserOAuth(OAuth):
        async def redirect_handler(self, authorization_url):
            await self.studio_flow.redirect(authorization_url)

        async def callback_handler(self):
            return await self.studio_flow.receive(super().callback_handler)

    return BrowserOAuth
