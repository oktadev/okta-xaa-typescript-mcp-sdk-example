/**
 * Configuration for the XAA Requesting App.
 *
 * All values come from your registration on https://xaa.dev:
 *  - XAA_CLIENT_ID / XAA_CLIENT_SECRET   → main requesting-app credentials
 *    (used for OIDC login and the RFC 8693 token exchange at the IdP)
 *  - MCP_CLIENT_ID / MCP_CLIENT_SECRET   → resource-scoped credentials
 *    (format: client_xxx-at-todo0-mcp; used only for the RFC 7523 JWT bearer grant)
 */
import { config as dotenvConfig } from 'dotenv';

dotenvConfig();

/**
 * xaa.dev's IdP does an exact-string match on the audience claim,
 * so trailing slashes must never sneak into these URLs.
 */
function trimSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

export const PORT = parseInt(process.env.PORT ?? '3001');
export const BASE_URL = trimSlash(process.env.BASE_URL ?? `http://localhost:${PORT}`);
export const REDIRECT_URI = `${BASE_URL}/callback`;

export const IDP_BASE_URL = trimSlash(process.env.IDP_BASE_URL ?? 'https://idp.xaa.dev');
export const AUTH_SERVER_URL = trimSlash(process.env.AUTH_SERVER_URL ?? 'https://auth.resource.xaa.dev');
export const MCP_SERVER_URL = trimSlash(process.env.MCP_SERVER_URL ?? 'https://mcp.xaa.dev/mcp');

export const XAA_CLIENT_ID = process.env.XAA_CLIENT_ID ?? '';
export const XAA_CLIENT_SECRET = process.env.XAA_CLIENT_SECRET ?? '';
export const MCP_CLIENT_ID = process.env.MCP_CLIENT_ID ?? '';
export const MCP_CLIENT_SECRET = process.env.MCP_CLIENT_SECRET ?? '';

// Some xaa.dev registrations show a separate credential pair for the RFC 8693
// token exchange (Step 2). If yours does, set these; otherwise the main app
// pair is used for both Step 1 (OIDC) and Step 2, per xaa.dev docs.
export const EXCHANGE_CLIENT_ID = process.env.EXCHANGE_CLIENT_ID || XAA_CLIENT_ID;
export const EXCHANGE_CLIENT_SECRET = process.env.EXCHANGE_CLIENT_SECRET || XAA_CLIENT_SECRET;

export const XAA_SCOPE = process.env.XAA_SCOPE ?? 'todos.read mcp.access';
export const OIDC_SCOPE = process.env.OIDC_SCOPE ?? 'openid email profile';

export function assertConfigured(): string[] {
  const missing: string[] = [];
  if (!XAA_CLIENT_ID) missing.push('XAA_CLIENT_ID');
  if (!XAA_CLIENT_SECRET) missing.push('XAA_CLIENT_SECRET');
  if (!MCP_CLIENT_ID) missing.push('MCP_CLIENT_ID');
  if (!MCP_CLIENT_SECRET) missing.push('MCP_CLIENT_SECRET');
  return missing;
}
