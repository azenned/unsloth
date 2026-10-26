# Remote MCP OAuth

Studio selects the public OAuth callback origin in this order:

1. `X-Forwarded-Proto: https` with `X-Forwarded-Host` (or preserved `Host`),
   when `UNSLOTH_STUDIO_TRUST_FORWARDED=1` is enabled.
2. `UNSLOTH_STUDIO_PUBLIC_URL`, for example `https://studio.example.com`.
3. The existing FastMCP localhost callback.

The public callback is `{origin}/api/mcp/oauth/callback`. Public origins must use
HTTPS and cannot contain credentials, paths, query parameters or fragments.
Set configuration in the backend launch environment and restart Studio.

The reverse proxy must forward `/api/` to the backend before any frontend
fallback. The callback must be accessible without proxy authentication.
Only trust forwarded headers when the backend is reachable through a trusted
proxy that overwrites them. For example, in an existing Nginx HTTPS server:

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:8888;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host $host;
    proxy_read_timeout 360s;
}
```

Omit callback query parameters from proxy/CDN access logs. When launching Uvicorn
directly, disable access logging or redact callback queries. The Studio launcher
already disables Uvicorn access logging.

In MCP Servers, enable **Use OAuth sign-in** and select **Test connection**.
Authorization opens in the user's browser; a link and manual callback completion
are available if needed. Dynamically registered client credentials are encrypted
and reused by account, endpoint and callback origin. The dialog shows the client
ID and whether a secret was issued, without returning secrets to the browser.
Leave the manual credential fields empty unless using a pre-registered client.

Discovery, PKCE, issuer metadata validation, code exchange and refresh use the MCP
SDK. The adapter was tested with FastMCP 3.4.11 and MCP 1.30.0; rerun the OAuth
regression tests after dependency upgrades.

Use one backend worker: pending OAuth flows live in memory and expire after five
minutes. Restarting cancels pending authorizations; stored credentials survive.
