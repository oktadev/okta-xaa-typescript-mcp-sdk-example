/**
 * XAA flow service — all Cross-App Access steps, built on the MCP TypeScript SDK.
 *
 *  Step 2  RFC 8693 Token Exchange   id_token → ID-JAG        discoverAndRequestJwtAuthGrant()
 *  Step 3  RFC 7523 JWT Bearer Grant ID-JAG   → access token  CrossAppAccessProvider token request (scope + client_secret_post)
 *  Step 4  MCP resource fetch        Bearer   → todos         Client + StreamableHTTPClientTransport
 *
 * Steps 2–4 run in one shot via CrossAppAccessProvider, the SDK's
 * OAuthClientProvider for SEP-990: the transport hits the MCP server, gets a 401,
 * discovers the auth server via RFC 9728, invokes our assertion callback for a
 * fresh ID-JAG, exchanges it, and retries — all automatically.
 */
import {
  Client,
  CrossAppAccessProvider,
  StreamableHTTPClientTransport,
  discoverAndRequestJwtAuthGrant,
  requestJwtAuthorizationGrant,
} from '@modelcontextprotocol/client';
import {
  AUTH_SERVER_URL,
  MCP_SERVER_URL,
  IDP_BASE_URL,
  EXCHANGE_CLIENT_ID,
  EXCHANGE_CLIENT_SECRET,
  MCP_CLIENT_ID,
  MCP_CLIENT_SECRET,
  XAA_SCOPE,
} from './config.js';

// ── JWT display helpers (decode only, no verification — for the demo UI) ────

export function decodeJwtPart(token: string, index: 0 | 1): Record<string, unknown> {
  try {
    const part = token.split('.')[index];
    if (!part) return {};
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf-8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function describeToken(raw: string): { raw: string; header?: unknown; payload?: unknown } {
  if (raw.split('.').length === 3) {
    return { raw, header: decodeJwtPart(raw, 0), payload: decodeJwtPart(raw, 1) };
  }
  return { raw };
}

// ── Step 4: MCP resource fetch ──────────────────────────────────────────────

export interface Todo {
  id?: string | number;
  title: string;
  completed: boolean;
  priority?: string;
  due?: string;
  [key: string]: unknown;
}

export interface McpFetchResult {
  resources: { uri: string; name?: string; mimeType?: string }[];
  resourceUri: string | null;
  rawText: string | null;
  todos: Todo[];
}

function normalizeTodos(rawText: string): Todo[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return [];
  }
  const list = Array.isArray(parsed)
    ? parsed
    : typeof parsed === 'object' && parsed !== null && Array.isArray((parsed as { todos?: unknown[] }).todos)
      ? (parsed as { todos: unknown[] }).todos
      : [];
  return list.flatMap((item): Todo[] => {
    if (typeof item !== 'object' || item === null) return [];
    const t = item as Record<string, unknown>;
    return [
      {
        ...t,
        id: (t.id ?? t.taskId) as string | number | undefined,
        title: String(t.title ?? t.task ?? t.name ?? t.description ?? 'Untitled task'),
        completed: Boolean(t.completed ?? t.done ?? t.status === 'completed'),
        priority: t.priority != null ? String(t.priority) : undefined,
        due: t.due != null ? String(t.due) : t.dueDate != null ? String(t.dueDate) : undefined,
      },
    ];
  });
}

async function fetchTodosWithClient(client: Client): Promise<McpFetchResult> {
  // The canonical todo resource URI is known, so list and read can run in
  // parallel instead of as two sequential round trips.
  const [listResult, directRead] = await Promise.all([
    client.listResources(),
    client.readResource({ uri: 'todo0://todos' }).catch(() => null),
  ]);
  const resources = listResult.resources;
  const summary = resources.map(r => ({ uri: r.uri, name: r.name, mimeType: r.mimeType }));

  let read = directRead;
  let resourceUri = 'todo0://todos';

  // Fallback for servers without todo0://todos: pick from the listed resources.
  if (!read) {
    const target = resources.find(r => /todo/i.test(r.uri)) ?? resources[0];
    if (!target) {
      return { resources: summary, resourceUri: null, rawText: null, todos: [] };
    }
    resourceUri = target.uri;
    read = await client.readResource({ uri: target.uri });
  }

  const first = read.contents[0];
  const rawText = first && 'text' in first && typeof first.text === 'string' ? first.text : null;

  return {
    resources: summary,
    resourceUri,
    rawText,
    todos: rawText ? normalizeTodos(rawText) : [],
  };
}

// ── CrossAppAccessProvider drives steps 2–4 ─────────────────────────────────

export interface AutoFlowEvents {
  onAssertion?: (ctx: { authorizationServerUrl: string; resourceUrl: string; scope?: string }) => void;
  onJag?: (jag: string) => void;
  onMcpFetchStart?: (accessToken: string | undefined) => void;
}

export async function runAutoFlow(
  idToken: string,
  events: AutoFlowEvents = {},
  idpTokenEndpoint?: string,
): Promise<{ accessToken: string | undefined; result: McpFetchResult }> {
  const provider = new CrossAppAccessProvider({
    assertion: async ctx => {
      events.onAssertion?.({
        authorizationServerUrl: ctx.authorizationServerUrl,
        resourceUrl: ctx.resourceUrl,
        scope: ctx.scope,
      });
      const jagOptions = {
        audience: ctx.authorizationServerUrl.replace(/\/+$/, ''),
        resource: ctx.resourceUrl,
        idToken,
        clientId: EXCHANGE_CLIENT_ID,
        clientSecret: EXCHANGE_CLIENT_SECRET,
        scope: ctx.scope ?? XAA_SCOPE,
        fetchFn: ctx.fetchFn,
      };
      // Use cached endpoint to skip per-call IdP discovery.
      const jag = idpTokenEndpoint
        ? await requestJwtAuthorizationGrant({ ...jagOptions, tokenEndpoint: idpTokenEndpoint })
        : await discoverAndRequestJwtAuthGrant({ ...jagOptions, idpUrl: IDP_BASE_URL });
      events.onJag?.(jag.jwtAuthGrant);
      return jag.jwtAuthGrant;
    },
    clientId: MCP_CLIENT_ID,
    clientSecret: MCP_CLIENT_SECRET,
    clientName: 'xaa-requesting-app-typescript',
  });

  // xaa.dev requires client_secret_post; override the SDK default (client_secret_basic).
  provider.saveClientInformation({
    client_id: MCP_CLIENT_ID,
    client_secret: MCP_CLIENT_SECRET,
    token_endpoint_auth_method: 'client_secret_post',
  } as Parameters<typeof provider.saveClientInformation>[0]);

  // xaa.dev metadata omits scope, so the provider skips it and issues an empty-scope token that the todo backend rejects with "Invalid or expired token".
  const origPrepareTokenRequest = provider.prepareTokenRequest.bind(provider);
  provider.prepareTokenRequest = async (scope?: string) => {
    const params = await origPrepareTokenRequest(scope ?? XAA_SCOPE);
    if (!params.has('scope')) params.set('scope', XAA_SCOPE);
    return params;
  };

  const transport = new StreamableHTTPClientTransport(new URL(MCP_SERVER_URL), {
    authProvider: provider,
  });
  const client = new Client({ name: 'xaa-requesting-app-typescript', version: '1.0.0' });
  await client.connect(transport);
  try {
    events.onMcpFetchStart?.(provider.tokens()?.access_token);
    const result = await fetchTodosWithClient(client);
    return { accessToken: provider.tokens()?.access_token, result };
  } finally {
    await client.close().catch(() => {});
  }
}
