# Employee Onboarding

A **Cross App Access (XAA / SEP-990)** demo built with the
[MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
([PR #1593](https://github.com/modelcontextprotocol/typescript-sdk/pull/1593)), registered as an
**MCP Requesting App on [xaa.dev](https://xaa.dev)**.

## The scenario

A new hire signs in once with company SSO. Their onboarding checklist loads immediately,
pulled live from the task system, with no "Connect your account" screens, no per-app OAuth
consent flows. IT wired up the connection at the IdP level; Cross App Access propagates
the user's identity across the trust boundary on each request.

The dashboard shows:

- A **progress ring** and stats for the onboarding checklist
- An **"Up next"** card suggesting the next step (required steps first)
- The **checklist** itself, with priorities mapped to _Required / Recommended / Optional_
- A **"Behind the scenes"** panel showing all four XAA steps live, with timings, decoded
  ID-JAG and access-token claims, and replay buttons (step-by-step SDK calls, or the
  one-shot `CrossAppAccessProvider` auto mode)

All checklist data is fetched at request time from xaa.dev's protected MCP server
(`todo0://todos`) with **read-only scopes** (`todos.read mcp.access`). Nothing is seeded or mocked.

## The XAA flow underneath

| Step                         | Protocol              | Endpoint                      | SDK API                                    |
| ---------------------------- | --------------------- | ----------------------------- | ------------------------------------------ |
| 1. Company SSO               | OIDC auth code + PKCE | `idp.xaa.dev/authorize`       | (plain OIDC)                               |
| 2. ID token → **ID-JAG**     | RFC 8693              | `idp.xaa.dev/token`           | `discoverAndRequestJwtAuthGrant()`         |
| 3. ID-JAG → **access token** | RFC 7523              | `auth.resource.xaa.dev/token` | provider / token request                   |
| 4. Fetch checklist           | MCP Streamable HTTP   | `mcp.xaa.dev/mcp`             | `Client` + `StreamableHTTPClientTransport` |

Auto mode uses `CrossAppAccessProvider`: 401 → RFC 9728 discovery → assertion callback → RFC 7523
exchange → retry, fully SDK-orchestrated.

## Prerequisites

- [Node.js](https://nodejs.org/) 18.17 or later
- A free [xaa.dev](https://xaa.dev) registration (email only, no account or password)

## Setup

### 1. Register a requesting app on xaa.dev

1. Go to the [requesting app registration page](https://xaa.dev/developer/register).
2. Enter your email address. It scopes which registered apps are visible to you; xaa.dev creates no account and sends no email.
3. Select **+ Register New App** and fill in the form:
   - **Application Name**: any label, for example `Onboarding App - Local Dev`
   - **Redirect URIs**: `http://localhost:3001/callback` (the match is exact, including scheme, host, port, and path)
   - **Connect to Resource**: select the **Todo MCP server** resource (`todo0-mcp`) and keep the `todos.read` and `mcp.access` scopes
4. Save the credentials from the confirmation modal.

Registration creates **two** OAuth clients, and mixing them up is the most common XAA mistake:

| Client | Credentials | Used in |
|---|---|---|
| Main client | `client_id` / `client_secret` | Step 1 (sign-in) and step 2 (token exchange) at the IdP |
| Resource client | `resource_client_id` / `resource_client_secret` (the ID looks like `client_xxx-at-todo0-mcp`) | Step 3 (JWT bearer grant) at the resource's authorization server |

Why two? Step 3 crosses a trust boundary. The IdP and the resource's authorization server are separate trust domains, so your app holds a separate identity at each. Using the main client's credentials in step 3 fails with `invalid_client`.

### 2. Configure the app

```bash
cp .env.example .env
```

Fill in `.env` with the credential pairs from the registration modal: app pair → `XAA_*`;
token-exchange pair → `EXCHANGE_*` (only if your registration issued a separate pair; leave
blank to fall back to the app pair); resource pair `client_xxx-at-todo0-mcp` → `MCP_*`.

### 3. Run it

```bash
npm install
npm start        # http://localhost:3001
```

> Note: uses port 3001. Stop any other app using that port before starting this one, since
> both share the registered redirect URI.

### 4. Try it

1. Open `http://localhost:3001` and select **Sign in with company SSO**. IdenX accepts any
   email address, so no real credentials are involved.
2. After sign-in, the flow runs automatically: the four steps light up in order in the
   "Behind the scenes" panel with real timings, and the checklist renders as soon as step 4
   delivers the data.
3. Select any step card to expand its decoded token. Check three things while you are there:
   - The ID-JAG's `aud` is the authorization server and its `resource` is the MCP server URL
   - The access token's `scope` claim contains `todos.read mcp.access`
   - The access token's `aud` matches the ID-JAG's `resource`, byte for byte
4. Try the **Replay auto (SDK provider)** button and watch `CrossAppAccessProvider` produce
   the same result through discovery alone, with no hardcoded authorization server URL.

## Caveats

- `client_secret_post` required for developer-registered clients (SDK defaults to Basic auth)
- `scope` must be sent explicitly in the RFC 7523 request or the access token is issued scope-less
- No trailing slashes in `audience` (exact string match at the IdP)
- IdP publishes OIDC discovery only; the SDK's metadata-discovery fallback handles it

## Files

```
src/config.ts        # env config (trailing-slash safe)
src/xaa.ts           # XAA steps built on the SDK (JAG, bearer grant, MCP fetch, auto provider)
src/server.ts        # Express: OIDC login + SSE endpoint streaming steps 2–4 live
public/index.html    # Employee onboarding UI (ring, up-next, checklist, behind-the-scenes)
```

## Links

This example uses the following open standards and libraries:

* [@modelcontextprotocol/client](https://www.npmjs.com/package/@modelcontextprotocol/client)
* [Express](https://expressjs.com)
* [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
* [RFC 7523: JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants](https://www.rfc-editor.org/rfc/rfc7523)
* [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)

## Help

Please post any questions as comments on the [blog post](https://developer.okta.com/blog/TODO), or visit our [Okta Developer Forums](https://devforum.okta.com/).

## License

Apache 2.0, see [LICENSE](LICENSE).
