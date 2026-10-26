# SPDX-License-Identifier: AGPL-3.0-only
import asyncio
import time
from urllib.parse import parse_qs, urlencode

import httpx
import pytest
from fastapi import FastAPI
from key_value.aio.stores.memory import MemoryStore
from mcp.shared.auth import OAuthClientInformationFull, OAuthMetadata

from core.inference import mcp_oauth as oauth
from routes.mcp_oauth import router

BASE = "https://studio.example"


@pytest.fixture(autouse = True)
def public(monkeypatch, tmp_path):
    monkeypatch.setenv("UNSLOTH_STUDIO_HOME", str(tmp_path))
    monkeypatch.setenv("UNSLOTH_STUDIO_PUBLIC_URL", BASE)
    oauth.flows.clear()
    yield
    oauth.flows.clear()


@pytest.mark.parametrize("value", ["http://studio.example", "https://u:p@studio.example", "https://studio.example/path", "https://studio.example?x=1", "", "https://studio.example:bad", " https://studio.example", "https://studio.example/#"])
def test_invalid_origin(value, monkeypatch):
    monkeypatch.setenv("UNSLOTH_STUDIO_PUBLIC_URL", value)
    with pytest.raises(ValueError):
        oauth.public_callback_url()


def test_local_fallback(monkeypatch):
    monkeypatch.delenv("UNSLOTH_STUDIO_PUBLIC_URL")
    assert oauth.public_callback_url() is None


def auth():
    return oauth.public_oauth_class()(mcp_url = "https://mcp.example/mcp", token_storage = MemoryStore())


def test_metadata_and_pkce_exchange():
    provider = auth()
    metadata = provider.context.client_metadata
    assert [str(u) for u in metadata.redirect_uris] == [BASE + oauth.CALLBACK_PATH]
    assert metadata.model_dump()["application_type"] == "web"
    assert not hasattr(provider, "redirect_port")
    provider.context.client_info = OAuthClientInformationFull(client_id = "client", redirect_uris = metadata.redirect_uris, token_endpoint_auth_method = "none")
    request = asyncio.run(provider._exchange_token_authorization_code("code", "verifier"))
    form = parse_qs(request.content.decode())
    assert form["redirect_uri"] == [BASE + oauth.CALLBACK_PATH]
    assert form["code_verifier"] == ["verifier"]


def test_callback_lifecycle():
    async def run():
        app = FastAPI()
        app.include_router(router)
        async with httpx.AsyncClient(transport = httpx.ASGITransport(app = app), base_url = BASE) as client:
            assert (await client.get(oauth.CALLBACK_PATH)).status_code == 400
            first = oauth.OAuthFlow("account1", "subject1", public = True, issuer = "https://issuer.example/")
            second = oauth.OAuthFlow("account2", "subject2", public = True)
            for flow, state in [(first, "random-state-one"), (second, "random-state-two")]:
                oauth.flows[flow.id] = flow
                await flow.redirect("https://issuer.example/authorize?" + urlencode({"state": state, "redirect_uri": oauth.public_callback_url()}))
            async def finish():
                assert await first.receive(None) == ("secret-code", "random-state-one")
                first.result = {"ok": True}
            first.task = asyncio.create_task(finish())
            path = oauth.CALLBACK_PATH
            assert (await client.get(path, params = {"state": "unknown", "code": "secret-code"})).status_code == 400
            assert (await client.get(path, params = {"state": "random-state-one", "code": "secret-code", "iss": "https://evil.example"})).status_code == 400
            response = await client.get(path, params = {"state": "random-state-one", "code": "secret-code", "iss": first.issuer})
            assert response.status_code == 200
            assert "secret-code" not in response.text
            assert response.headers["cache-control"] == "no-store"
            assert not second.callback.done()
            assert (await client.get(path, params = {"state": "random-state-one", "code": "replay"})).status_code == 400
            second.created = time.monotonic() - 301
            assert (await client.get(path, params = {"state": "random-state-two", "code": "expired"})).status_code == 400
    asyncio.run(run())


def test_sdk_authorization_and_denial():
    async def run():
        provider = auth()
        flow = oauth.OAuthFlow("account", "subject")
        token = oauth.active_flow.set(flow)
        provider.context.client_info = OAuthClientInformationFull(client_id = "client", redirect_uris = provider.context.client_metadata.redirect_uris)
        provider.context.oauth_metadata = OAuthMetadata(issuer = "https://issuer.example", authorization_endpoint = "https://issuer.example/authorize", token_endpoint = "https://issuer.example/token", response_types_supported = ["code"])
        try:
            task = asyncio.create_task(provider._perform_authorization())
            for _ in range(50):
                if flow.authorization_url:
                    break
                await asyncio.sleep(0)
            query = parse_qs(flow.authorization_url.split("?", 1)[1])
            assert query["code_challenge_method"] == ["S256"]
            assert len(query["state"][0]) >= 32
            flow.complete(oauth.public_callback_url() + "?" + urlencode({"state": query["state"][0], "error": "access_denied", "error_description": "sensitive detail"}))
            with pytest.raises(ValueError, match = "denied"):
                await task
        finally:
            oauth.active_flow.reset(token)
    asyncio.run(run())


def test_simulated_oauth_server_pkce_tokens_and_tools(caplog):
    import base64
    import hashlib
    import json

    async def run():
        provider = auth()
        flow = oauth.OAuthFlow("account", "subject")
        oauth.flows[flow.id] = flow
        token = oauth.active_flow.set(flow)
        registration = []

        def remote(request):
            if request.url.path == "/mcp":
                if request.headers.get("Authorization") == "Bearer secret-access-token":
                    return httpx.Response(200, json = {"tools": [{"name": "search"}]})
                return httpx.Response(401, headers = {"WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example/.well-known/oauth-protected-resource"'})
            if "oauth-protected-resource" in request.url.path:
                return httpx.Response(200, json = {"resource": "https://mcp.example/mcp", "authorization_servers": ["https://issuer.example"]})
            if "oauth-authorization-server" in request.url.path:
                return httpx.Response(200, json = {"issuer": "https://issuer.example", "authorization_endpoint": "https://issuer.example/authorize", "token_endpoint": "https://issuer.example/token", "registration_endpoint": "https://issuer.example/register", "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"]})
            if request.url.path == "/register":
                data = json.loads(request.content)
                registration.append(data)
                assert data["application_type"] == "web"
                assert data["redirect_uris"] == [oauth.public_callback_url()]
                return httpx.Response(201, json = {**data, "client_id": "registered", "token_endpoint_auth_method": "none"})
            if request.url.path == "/token":
                data = parse_qs(request.content.decode())
                query = parse_qs(flow.authorization_url.split("?", 1)[1])
                challenge = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
                assert challenge == query["code_challenge"][0]
                assert data["code"] == ["secret-code"]
                assert data["redirect_uri"] == [oauth.public_callback_url()]
                return httpx.Response(200, json = {"access_token": "secret-access-token", "refresh_token": "secret-refresh-token", "token_type": "Bearer", "expires_in": 3600})
            return httpx.Response(404)

        async def connect():
            async with httpx.AsyncClient(transport = httpx.MockTransport(remote), auth = provider) as client:
                response = await client.get("https://mcp.example/mcp")
                assert response.json()["tools"][0]["name"] == "search"
                flow.result = {"ok": True, "tool_count": 1}

        try:
            flow.task = asyncio.create_task(connect())
            for _ in range(1000):
                if flow.authorization_url:
                    break
                await asyncio.sleep(.001)
            assert flow.authorization_url, flow.task.exception() if flow.task.done() else "No authorization URL"
            query = parse_qs(flow.authorization_url.split("?", 1)[1])
            app = FastAPI()
            app.include_router(router)
            async with httpx.AsyncClient(transport = httpx.ASGITransport(app = app), base_url = BASE) as browser:
                response = await browser.get(oauth.CALLBACK_PATH, params = {"state": query["state"][0], "code": "secret-code", "iss": flow.issuer.rstrip("/")})
                assert response.status_code == 200, response.text
            assert len(registration) == 1
            reloaded = auth()
            await reloaded._initialize()
            assert reloaded.context.current_tokens.access_token == "secret-access-token"
            assert reloaded.context.token_expiry_time > time.time()
            assert "secret-access-token" not in caplog.text
            assert "secret-refresh-token" not in caplog.text
            assert "secret-code" not in caplog.text
        finally:
            oauth.active_flow.reset(token)
            if flow.task and not flow.task.done():
                flow.task.cancel()
                await asyncio.gather(flow.task, return_exceptions = True)
    asyncio.run(run())


def test_encrypted_storage_and_account_isolation(tmp_path):
    from mcp.shared.auth import OAuthToken
    from utils.account_context import AccountContext, bind_account, reset_account
    from utils.paths import studio_db_path

    async def run():
        owner = oauth.encrypted_token_storage("server")
        await owner.set_tokens(OAuthToken(access_token = "private-access", refresh_token = "private-refresh", expires_in = 300))
        assert (await owner.get_tokens()).access_token == "private-access"
        assert b"private-access" not in studio_db_path().read_bytes()
        assert b"private-refresh" not in studio_db_path().read_bytes()
        account = bind_account(AccountContext("other", "other"))
        try:
            other = oauth.encrypted_token_storage("server")
            assert await other.get_tokens() is None
        finally:
            reset_account(account)
        assert await oauth.encrypted_token_storage("different-server").get_tokens() is None
        await owner.clear()
        assert await owner.get_tokens() is None
    asyncio.run(run())


def test_sensitive_sdk_errors_are_redacted(caplog):
    import logging
    auth()  # Installs the SDK log filter.
    try:
        raise ValueError("secret-code secret-token")
    except ValueError:
        logging.getLogger("mcp.client.auth.oauth2").exception("secret-code secret-token")
    assert "secret-code" not in caplog.text
    assert "secret-token" not in caplog.text
    assert "MCP OAuth protocol failed" in caplog.text



def test_mcp_client_selects_public_provider_without_allocating_port(monkeypatch):
    from core.inference import mcp_client
    import importlib

    module = importlib.import_module("fastmcp.client.auth.oauth")
    def no_local_port(*args, **kwargs):
        raise AssertionError("Public OAuth must not allocate a loopback callback port")
    monkeypatch.setattr(module, "find_available_port", no_local_port)
    monkeypatch.setattr(mcp_client, "_oauth_store", lambda: MemoryStore())
    provider = mcp_client._oauth("https://mcp.example/mcp")
    assert str(provider.context.client_metadata.redirect_uris[0]) == BASE + oauth.CALLBACK_PATH


@pytest.mark.parametrize("trusted,headers,expected", [
    (True, {"x-forwarded-proto": "https", "x-forwarded-host": "proxy.example:8443"}, "https://proxy.example:8443"),
    (True, {"x-forwarded-proto": "https", "host": "preserved.example"}, "https://preserved.example"),
    (True, {"x-forwarded-proto": "http", "x-forwarded-host": "proxy.example"}, BASE),
    (False, {"x-forwarded-proto": "https", "x-forwarded-host": "untrusted.example"}, BASE),
    (True, {"x-forwarded-proto": "https", "x-forwarded-host": "evil.example/path"}, BASE),
    (True, {"x-forwarded-proto": "https", "x-forwarded-host": "evil.example,proxy.example"}, BASE),
    (True, [("x-forwarded-proto", "https"), ("x-forwarded-proto", "http")], BASE),
    (True, [("x-forwarded-proto", "https"), ("x-forwarded-host", "a.example"), ("x-forwarded-host", "b.example")], BASE),
])
def test_proxy_origin_priority(monkeypatch, trusted, headers, expected):
    monkeypatch.setenv("UNSLOTH_STUDIO_TRUST_FORWARDED", "1" if trusted else "0")
    async def run():
        app = FastAPI()
        app.add_middleware(oauth.OAuthCallbackOriginMiddleware)
        @app.get("/origin")
        async def origin():
            return {"callback": oauth.public_callback_url()}
        async with httpx.AsyncClient(transport = httpx.ASGITransport(app = app), base_url = BASE) as client:
            response = await client.get("/origin", headers = headers)
            assert response.json()["callback"] == expected + oauth.CALLBACK_PATH
        assert oauth.public_callback_url() == BASE + oauth.CALLBACK_PATH
    asyncio.run(run())


def test_proxy_without_environment_and_local_fallback(monkeypatch):
    monkeypatch.delenv("UNSLOTH_STUDIO_PUBLIC_URL")
    monkeypatch.setenv("UNSLOTH_STUDIO_TRUST_FORWARDED", "1")
    async def run():
        app = FastAPI()
        app.add_middleware(oauth.OAuthCallbackOriginMiddleware)
        tasks = []
        @app.get("/origin")
        async def origin():
            async def later():
                await asyncio.sleep(.01)
                return oauth.public_callback_url()
            task = asyncio.create_task(later())
            tasks.append(task)
            return {"callback": oauth.public_callback_url()}
        async with httpx.AsyncClient(transport = httpx.ASGITransport(app = app), base_url = BASE) as client:
            responses = await asyncio.gather(*[
                client.get("/origin", headers = {"x-forwarded-proto": "https", "x-forwarded-host": host})
                for host in ("first.example", "second.example")
            ])
            assert {r.json()["callback"] for r in responses} == {
                "https://first.example" + oauth.CALLBACK_PATH,
                "https://second.example" + oauth.CALLBACK_PATH,
            }
            assert set(await asyncio.gather(*tasks)) == {r.json()["callback"] for r in responses}
            response = await client.get("/origin")
            assert response.json()["callback"] is None
            await tasks[-1]
        assert oauth.public_callback_url() is None
    asyncio.run(run())


def test_callback_uses_origin_pinned_to_flow(monkeypatch):
    monkeypatch.delenv("UNSLOTH_STUDIO_PUBLIC_URL")
    async def run():
        flow = oauth.OAuthFlow("account", "subject", public = True)
        oauth.flows[flow.id] = flow
        pinned = "https://original.example" + oauth.CALLBACK_PATH
        await flow.redirect("https://issuer.example/authorize?" + urlencode({"state": "state", "redirect_uri": pinned}))
        async def finish():
            assert await flow.receive(None) == ("code", "state")
            flow.result = {"ok": True}
        flow.task = asyncio.create_task(finish())
        app = FastAPI()
        app.include_router(router)
        async with httpx.AsyncClient(transport = httpx.ASGITransport(app = app), base_url = "http://internal") as client:
            response = await client.get(oauth.CALLBACK_PATH, params = {"state": "state", "code": "code"})
            assert response.status_code == 200
        await flow.task
    asyncio.run(run())


def test_dynamic_registration_visible_after_test_save_and_reopen(monkeypatch):
    from models.mcp_servers import McpServerCreate, McpServerTestRequest, McpServerUpdate
    from routes import mcp_servers
    from mcp.shared.auth import OAuthToken

    async def run():
        url = "https://mcp.example/mcp"
        storage = oauth.encrypted_token_storage(oauth.public_oauth_storage_key(url, oauth.public_callback_url()))
        await storage.set_client_info(OAuthClientInformationFull(
            client_id = "dynamic-client", client_secret = "private-dynamic-secret",
            redirect_uris = [oauth.public_callback_url()], token_endpoint_auth_method = "client_secret_basic",
            issuer = "https://issuer.example",
        ))
        await storage.set_tokens(OAuthToken(access_token = "private-access-token", refresh_token = "private-refresh-token"))
        async def list_tools(**kwargs):
            return [{"name": "search"}]
        monkeypatch.setattr(mcp_servers, "list_tools_async", list_tools)
        result = await mcp_servers.test_mcp_server(McpServerTestRequest(url = url, use_oauth = True), current_subject = "user")
        assert result.oauth_registered_client_id == "dynamic-client"
        assert result.has_oauth_registered_client_secret
        saved = await mcp_servers.create_mcp_server(McpServerCreate(display_name = "Example", url = url, use_oauth = True), current_subject = "user")
        assert saved.oauth_registered_client_id == "dynamic-client"
        assert saved.has_oauth_registered_client_secret
        # Saving blank manual inputs must retain the dynamic client and its tokens.
        reopened = await mcp_servers.update_mcp_server(saved.id, McpServerUpdate(display_name = "Renamed", use_oauth = True, oauth_client_id = None), current_subject = "user")
        assert reopened.oauth_registered_client_id == "dynamic-client"
        assert reopened.oauth_client_id is None
        info = await storage.get_client_info()
        assert info.token_endpoint_auth_method == "client_secret_basic"
        assert info.issuer == "https://issuer.example"
        assert (await storage.get_tokens()).access_token == "private-access-token"
        for response in (result, saved, reopened):
            assert "private-dynamic-secret" not in response.model_dump_json()
            assert "private-access-token" not in response.model_dump_json()
            assert "private-refresh-token" not in response.model_dump_json()
    asyncio.run(run())


def test_registration_status_without_secret_and_origin_isolation():
    async def run():
        url = "https://mcp.example/mcp"
        storage = oauth.encrypted_token_storage(oauth.public_oauth_storage_key(url, oauth.public_callback_url()))
        await storage.set_client_info(OAuthClientInformationFull(client_id = "public-client", redirect_uris = [oauth.public_callback_url()]))
        assert oauth.oauth_registration_status(url) == {"oauth_registered_client_id": "public-client", "has_oauth_registered_client_secret": False}
        assert oauth.oauth_registration_status("https://different.example/mcp") == {}
        token = oauth._request_callback.set("https://different-studio.example" + oauth.CALLBACK_PATH)
        try:
            assert oauth.oauth_registration_status(url) == {}
        finally:
            oauth._request_callback.reset(token)
    asyncio.run(run())
