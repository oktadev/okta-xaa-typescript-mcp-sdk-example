/**
 * XAA Requesting App (TypeScript) — web server.
 *
 *  Step 1  OIDC login (auth code + PKCE) against https://idp.xaa.dev
 *  Steps 2–4 run server-side via CrossAppAccessProvider and stream live to
 *  the dashboard over SSE (GET /api/flow).
 */
import express from 'express';
import cookieParser from 'cookie-parser';
import escapeHtml from 'escape-html';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import * as client from 'openid-client';
import {
  PORT,
  BASE_URL,
  REDIRECT_URI,
  IDP_BASE_URL,
  AUTH_SERVER_URL,
  MCP_SERVER_URL,
  XAA_CLIENT_ID,
  XAA_CLIENT_SECRET,
  XAA_SCOPE,
  OIDC_SCOPE,
  assertConfigured,
} from './config.js';
import {
  describeToken,
  runAutoFlow,
} from './xaa.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Sessions (in-memory, demo only) ─────────────────────────────────────────

interface Session {
  pkceVerifier?: string;
  state?: string;
  nonce?: string;
  idToken?: string;
  claims?: Record<string, unknown>;
}

const sessions = new Map<string, Session>();

function getSession(req: express.Request, res: express.Response): Session {
  let sid = req.cookies?.sid as string | undefined;
  if (!sid || !sessions.has(sid)) {
    sid = crypto.randomBytes(16).toString('hex');
    sessions.set(sid, {});
    res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax' });
  }
  return sessions.get(sid)!;
}

// ── OIDC discovery (cached) ──────────────────────────────────────────────────

// openid-client handles discovery, PKCE, and — importantly — ID token
// signature and claim validation, which hand-rolled code usually skips.
let idpConfig: client.Configuration | undefined;

async function getIdpConfig(): Promise<client.Configuration> {
  if (!idpConfig) {
    idpConfig = await client.discovery(
      new URL(IDP_BASE_URL),
      XAA_CLIENT_ID,
      XAA_CLIENT_SECRET,
    );
  }
  return idpConfig;
}

// The IdP token endpoint, reused in step 2 to skip a second discovery round trip.
async function getIdpTokenEndpoint(): Promise<string | undefined> {
  const config = await getIdpConfig();
  return config.serverMetadata().token_endpoint;
}

// Pre-establish TLS connections to xaa.dev hosts so flow requests reuse warm sockets. Fire-and-forget; only static metadata is fetched, never user data.
function warmConnections(): void {
  void Promise.allSettled([
    getIdpConfig(),
    fetch(`${AUTH_SERVER_URL}/.well-known/oauth-authorization-server`).then(r => r.arrayBuffer()),
    fetch(MCP_SERVER_URL, { method: 'HEAD' }).then(r => r.arrayBuffer()),
  ]);
}

// ── Step 1: OIDC login with PKCE ─────────────────────────────────────────────

app.get('/login', async (req, res) => {
  const missing = assertConfigured();
  if (missing.length > 0) {
    res.status(500).send(`Missing configuration in .env: ${missing.join(', ')} — see README.md`);
    return;
  }

  const session = getSession(req, res);
  const config = await getIdpConfig();

  const verifier = client.randomPKCECodeVerifier();
  session.pkceVerifier = verifier;
  session.state = client.randomState();
  session.nonce = client.randomNonce();

  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: OIDC_SCOPE,
    state: session.state,
    nonce: session.nonce,
    code_challenge: await client.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  });

  console.log(`[login] redirecting to ${url.href}`);
  res.redirect(url.href);
});

app.get('/callback', async (req, res) => {
  const session = getSession(req, res);
  const { error, error_description } = req.query as Record<string, string>;

  if (error) {
    res.status(400).send(`IdP error: ${escapeHtml(error)} — ${escapeHtml(error_description ?? '')}`);
    return;
  }

  try {
    const config = await getIdpConfig();

    // Verifies the ID token signature against the IdP's published keys, plus
    // the iss, aud, and exp claims, and checks state and nonce for us.
    const tokens = await client.authorizationCodeGrant(
      config,
      new URL(req.originalUrl, BASE_URL),
      {
        pkceCodeVerifier: session.pkceVerifier,
        expectedState: session.state,
        expectedNonce: session.nonce,
      },
    );

    if (!tokens.id_token) throw new Error('no id_token in token response');
    const claims = (tokens.claims() ?? {}) as Record<string, unknown>;

    session.idToken = tokens.id_token;
    session.claims = claims;
    console.log(`[login] ✅ logged in as ${String(claims.email ?? claims.sub)}`);
    res.redirect('/');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[callback] ❌', msg);

    // A stale callback is a client-side problem, not a server fault: a
    // refreshed /callback page, a reused code, or a restart that cleared the
    // in-memory session. openid-client reports all of these as
    // OAUTH_INVALID_RESPONSE, whose message ("invalid response encountered")
    // says nothing useful to the person looking at the page.
    const code = (err as { code?: string }).code;
    if (code === 'OAUTH_INVALID_RESPONSE' || err instanceof client.AuthorizationResponseError) {
      res
        .status(400)
        .send(
          'Sign-in could not be completed: the link was already used, or the session expired. <a href="/login">Try again</a>',
        );
      return;
    }

    res.status(500).send(`Login failed: ${escapeHtml(msg)} <br/><a href="/login">Try again</a>`);
  }
});

app.get('/logout', (req, res) => {
  const sid = req.cookies?.sid as string | undefined;
  if (sid) sessions.delete(sid);
  res.clearCookie('sid');
  res.redirect('/');
});

// ── Session/config info for the UI ──────────────────────────────────────────

app.get('/api/session', (req, res) => {
  warmConnections(); // page just loaded — a flow run is likely imminent
  const session = getSession(req, res);
  res.json({
    loggedIn: Boolean(session.idToken),
    user: session.claims
      ? { sub: session.claims.sub, email: session.claims.email, name: session.claims.name }
      : null,
    idToken: session.idToken ? describeToken(session.idToken) : null,
    config: {
      idpBaseUrl: IDP_BASE_URL,
      authServerUrl: AUTH_SERVER_URL,
      mcpServerUrl: MCP_SERVER_URL,
      scope: XAA_SCOPE,
      redirectUri: REDIRECT_URI,
      missing: assertConfigured(),
    },
  });
});

// ── Steps 2–4 streamed over SSE ──────────────────────────────────────────────

type SseEvent =
  | { type: 'step'; step: string; status: 'start' | 'done' | 'error'; ms?: number; data?: unknown; error?: string }
  | { type: 'flow'; status: 'done' | 'error'; error?: string };

app.get('/api/flow', async (req, res) => {
  const session = getSession(req, res);
  if (!session.idToken) {
    res.status(401).json({ error: 'not logged in' });
    return;
  }
  const idToken = session.idToken;
  // Cached at login; lets step 2 hit the IdP token endpoint directly instead
  // of re-discovering the metadata on every run.
  const idpTokenEndpoint = await getIdpTokenEndpoint().catch(() => undefined);

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.flushHeaders();

  const emit = (event: SseEvent) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  try {
    const t0 = Date.now();
    let jagAt = t0;
    let mcpAt = t0;
    emit({
      type: 'step', step: 'jag', status: 'start',
      data: { note: 'CrossAppAccessProvider connecting — RFC 9728 discovery, then assertion callback' },
    });
    const { result } = await runAutoFlow(idToken, {
      onAssertion: ctx => {
        emit({ type: 'step', step: 'jag', status: 'start', data: { discovered: ctx } });
      },
      onJag: jag => {
        jagAt = Date.now();
        emit({ type: 'step', step: 'jag', status: 'done', ms: jagAt - t0, data: { token: describeToken(jag) } });
        emit({ type: 'step', step: 'token', status: 'start', data: { note: 'provider exchanging ID-JAG (RFC 7523)' } });
      },
      onMcpFetchStart: accessToken => {
        mcpAt = Date.now();
        emit({
          type: 'step', step: 'token', status: 'done', ms: mcpAt - jagAt,
          data: { token: accessToken ? describeToken(accessToken) : null },
        });
        emit({ type: 'step', step: 'mcp', status: 'start', data: { request: { mcpServerUrl: MCP_SERVER_URL } } });
      },
    }, idpTokenEndpoint);
    const tEnd = Date.now();
    emit({ type: 'step', step: 'mcp', status: 'done', ms: tEnd - mcpAt, data: result });
    emit({ type: 'flow', status: 'done' });
  } catch (err) {
    emit({ type: 'flow', status: 'error', error: err instanceof Error ? err.message : String(err) });
  } finally {
    res.end();
  }
});

// ── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════════════════╗');
  console.log('║     🌅 Employee Onboarding (XAA · xaa.dev demo)     ║');
  console.log('╚════════════════════════════════════════════════════╝');
  console.log(`  App:          ${BASE_URL}`);
  console.log(`  IdP:          ${IDP_BASE_URL}`);
  console.log(`  Auth server:  ${AUTH_SERVER_URL}`);
  console.log(`  MCP server:   ${MCP_SERVER_URL}`);
  const missing = assertConfigured();
  if (missing.length > 0) console.log(`  ⚠️  Missing .env values: ${missing.join(', ')}`);
  console.log(`\n  👉 Open ${BASE_URL}\n`);
});
