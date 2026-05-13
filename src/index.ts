import fs from 'node:fs/promises';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import cors from 'cors';
import express, { type Request, type Response } from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import * as z from 'zod/v4';

type LinkedInTokenRecord = {
  accessToken: string;
  expiresAt: string;
  scope: string;
  memberId: string;
  memberName?: string;
  refreshToken?: string;
  refreshTokenExpiresAt?: string;
  connectedAt: string;
};

type OAuthStateRecord = {
  createdAt: number;
  returnTo?: string;
};

const port = Number.parseInt(process.env.PORT ?? '3000', 10);
const host = process.env.HOST ?? '0.0.0.0';
const baseUrl = process.env.BASE_URL?.replace(/\/$/, '') ?? `http://localhost:${port}`;
const tokenStorePath = process.env.LINKEDIN_TOKEN_STORE ?? '/data/linkedin-token.json';
const linkedinClientId = process.env.LINKEDIN_CLIENT_ID;
const linkedinClientSecret = process.env.LINKEDIN_CLIENT_SECRET;
const linkedinRedirectUri = process.env.LINKEDIN_REDIRECT_URI ?? `${baseUrl}/auth/linkedin/callback`;
const linkedinScopes = (process.env.LINKEDIN_SCOPES ?? 'r_liteprofile w_member_social')
  .split(/\s+/)
  .filter(Boolean)
  .join(' ');

if (!linkedinClientId || !linkedinClientSecret) {
  console.warn('LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET must be set for OAuth to work.');
}

const oauthStates = new Map<string, OAuthStateRecord>();
const transports = new Map<string, StreamableHTTPServerTransport>();
let tokenCache: LinkedInTokenRecord | null = null;

const app = express();
app.set('trust proxy', true);
app.use(cors({ origin: '*', exposedHeaders: ['Mcp-Session-Id', 'Mcp-Protocol-Version'] }));
app.use(express.json({ limit: '1mb' }));

async function loadTokenRecord(): Promise<LinkedInTokenRecord | null> {
  if (tokenCache) {
    return tokenCache;
  }

  try {
    const raw = await fs.readFile(tokenStorePath, 'utf8');
    tokenCache = JSON.parse(raw) as LinkedInTokenRecord;
    return tokenCache;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }

    throw error;
  }
}

async function saveTokenRecord(record: LinkedInTokenRecord | null): Promise<void> {
  tokenCache = record;

  if (!record) {
    await fs.rm(tokenStorePath, { force: true });
    return;
  }

  await fs.mkdir(path.dirname(tokenStorePath), { recursive: true });
  await fs.writeFile(tokenStorePath, `${JSON.stringify(record, null, 2)}\n`, 'utf8');
}

function isTokenStillValid(record: LinkedInTokenRecord | null): boolean {
  if (!record) {
    return false;
  }

  const expiresAt = new Date(record.expiresAt).getTime();
  return Number.isFinite(expiresAt) && expiresAt > Date.now();
}

function buildLinkedInAuthorizeUrl(state: string): string {
  const url = new URL('https://www.linkedin.com/oauth/v2/authorization');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', linkedinClientId ?? '');
  url.searchParams.set('redirect_uri', linkedinRedirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('scope', linkedinScopes);
  return url.toString();
}

async function exchangeAuthorizationCode(code: string): Promise<LinkedInTokenRecord> {
  if (!linkedinClientId || !linkedinClientSecret) {
    throw new Error('LinkedIn OAuth is not configured.');
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: linkedinClientId,
    client_secret: linkedinClientSecret,
    redirect_uri: linkedinRedirectUri
  });

  const response = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });

  if (!response.ok) {
    throw new Error(`LinkedIn token exchange failed (${response.status}): ${await response.text()}`);
  }

  const data = (await response.json()) as {
    access_token: string;
    expires_in: number;
    refresh_token?: string;
    refresh_token_expires_in?: number;
    scope?: string;
  };

  const profile = await fetchLinkedInProfile(data.access_token);

  return {
    accessToken: data.access_token,
    expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
    scope: data.scope ?? linkedinScopes,
    memberId: profile.memberId,
    memberName: profile.memberName,
    refreshToken: data.refresh_token,
    refreshTokenExpiresAt: data.refresh_token_expires_in
      ? new Date(Date.now() + data.refresh_token_expires_in * 1000).toISOString()
      : undefined,
    connectedAt: new Date().toISOString()
  };
}

async function fetchLinkedInProfile(accessToken: string): Promise<{ memberId: string; memberName?: string }> {
  const commonHeaders = {
    Authorization: `Bearer ${accessToken}`,
    'X-Restli-Protocol-Version': '2.0.0'
  };

  const meResponse = await fetch('https://api.linkedin.com/v2/me', { headers: commonHeaders });
  if (meResponse.ok) {
    const me = (await meResponse.json()) as {
      id?: string;
      localizedFirstName?: string;
      localizedLastName?: string;
    };

    if (me.id) {
      const memberName = [me.localizedFirstName, me.localizedLastName].filter(Boolean).join(' ').trim() || undefined;
      return { memberId: me.id, memberName };
    }
  }

  const userInfoResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` }
  });

  if (!userInfoResponse.ok) {
    throw new Error(`Unable to fetch LinkedIn profile (${meResponse.status}/${userInfoResponse.status})`);
  }

  const userInfo = (await userInfoResponse.json()) as { sub?: string; name?: string };
  if (!userInfo.sub) {
    throw new Error('LinkedIn profile response did not include a member id.');
  }

  return { memberId: userInfo.sub, memberName: userInfo.name };
}

async function postToLinkedIn(accessToken: string, memberId: string, text: string, visibility: 'PUBLIC' | 'CONNECTIONS'): Promise<string> {
  const response = await fetch('https://api.linkedin.com/v2/ugcPosts', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'X-Restli-Protocol-Version': '2.0.0'
    },
    body: JSON.stringify({
      author: `urn:li:person:${memberId}`,
      lifecycleState: 'PUBLISHED',
      specificContent: {
        'com.linkedin.ugc.ShareContent': {
          shareCommentary: { text },
          shareMediaCategory: 'NONE'
        }
      },
      visibility: {
        'com.linkedin.ugc.MemberNetworkVisibility': visibility
      }
    })
  });

  if (!response.ok) {
    throw new Error(`LinkedIn post failed (${response.status}): ${await response.text()}`);
  }

  const location = response.headers.get('x-restli-id') ?? response.headers.get('location') ?? 'created';
  return location;
}

function createServer(): McpServer {
  const server = new McpServer(
    { name: 'linkedin-publisher', version: '1.0.0' },
    { capabilities: { logging: {} } }
  );

  server.registerTool(
    'linkedin_connection_status',
    {
      description: 'Check whether LinkedIn OAuth is connected for this deployment.',
      inputSchema: z.object({})
    },
    async (): Promise<CallToolResult> => {
      const record = await loadTokenRecord();
      return {
        content: [
          {
            type: 'text',
            text: record
              ? `Connected as ${record.memberName ?? record.memberId}. Token valid: ${isTokenStillValid(record) ? 'yes' : 'no'}.`
              : 'Not connected. Open /auth/linkedin/start to connect a LinkedIn account.'
          }
        ]
      };
    }
  );

  server.registerTool(
    'linkedin_connect',
    {
      description: 'Get the LinkedIn authorization URL for this deployment.',
      inputSchema: z.object({ returnTo: z.string().url().optional() })
    },
    async ({ returnTo }: { returnTo?: string }): Promise<CallToolResult> => {
      const state = randomBytes(24).toString('hex');
      oauthStates.set(state, { createdAt: Date.now(), returnTo });
      return {
        content: [
          {
            type: 'text',
            text: `Open this URL to connect LinkedIn:\n${buildLinkedInAuthorizeUrl(state)}\n\nCallback: ${linkedinRedirectUri}`
          }
        ]
      };
    }
  );

  server.registerTool(
    'linkedin_post',
    {
      description: 'Post a text update to the connected LinkedIn member account.',
      inputSchema: z.object({
        text: z.string().min(1).max(3000),
        visibility: z.enum(['PUBLIC', 'CONNECTIONS']).default('PUBLIC')
      })
    },
    async (
      { text, visibility }: { text: string; visibility: 'PUBLIC' | 'CONNECTIONS' }
    ): Promise<CallToolResult> => {
      const record = await loadTokenRecord();
      if (!isTokenStillValid(record)) {
        return {
          isError: true,
          content: [
            {
              type: 'text',
              text: `LinkedIn is not connected or the token expired. Open ${baseUrl}/auth/linkedin/start and reconnect before posting.`
            }
          ]
        };
      }

      const postId = await postToLinkedIn(record!.accessToken, record!.memberId, text, visibility);
      return {
        content: [
          {
            type: 'text',
            text: `Posted to LinkedIn successfully. Result: ${postId}`
          }
        ]
      };
    }
  );

  return server;
}

async function renderStatusPage(response: Response): Promise<void> {
  const record = await loadTokenRecord();
  const connected = isTokenStillValid(record);

  response.type('html').send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>LinkedIn MCP Server</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; max-width: 860px; margin: 48px auto; padding: 0 24px; line-height: 1.5; }
      .card { border: 1px solid #e5e7eb; border-radius: 16px; padding: 24px; margin: 16px 0; }
      .ok { color: #166534; }
      .bad { color: #991b1b; }
      code, pre { background: #f3f4f6; border-radius: 8px; }
      pre { padding: 16px; overflow: auto; }
      a { color: #0f766e; }
    </style>
  </head>
  <body>
    <h1>LinkedIn MCP Server</h1>
    <div class="card">
      <p>Status: <strong class="${connected ? 'ok' : 'bad'}">${connected ? 'LinkedIn connected' : 'Not connected'}</strong></p>
      <p>MCP endpoint: <code>${baseUrl}/mcp</code></p>
      <p>OAuth callback: <code>${linkedinRedirectUri}</code></p>
      <p>Scopes: <code>${linkedinScopes}</code></p>
      <p><a href="/auth/linkedin/start">Connect LinkedIn</a> · <a href="/auth/linkedin/disconnect" onclick="fetch('/auth/linkedin/disconnect', { method: 'POST' }).then(() => location.reload()); return false;">Disconnect</a></p>
    </div>
    <div class="card">
      <h2>Available tools</h2>
      <ul>
        <li><code>linkedin_connection_status</code></li>
        <li><code>linkedin_connect</code></li>
        <li><code>linkedin_post</code></li>
      </ul>
    </div>
    <div class="card">
      <p>This deployment stores one LinkedIn authorization record in <code>${tokenStorePath}</code>.</p>
    </div>
  </body>
</html>`);
}

app.get('/', async (_request, response) => {
  await renderStatusPage(response);
});

app.get('/health', async (_request, response) => {
  const record = await loadTokenRecord();
  response.json({ ok: true, linkedInConnected: isTokenStillValid(record) });
});

app.get('/auth/linkedin/start', (request, response) => {
  const state = randomUUID();
  oauthStates.set(state, {
    createdAt: Date.now(),
    returnTo: typeof request.query.returnTo === 'string' ? request.query.returnTo : undefined
  });

  response.redirect(buildLinkedInAuthorizeUrl(state));
});

app.get('/auth/linkedin/callback', async (request, response) => {
  const code = typeof request.query.code === 'string' ? request.query.code : undefined;
  const state = typeof request.query.state === 'string' ? request.query.state : undefined;
  const error = typeof request.query.error === 'string' ? request.query.error : undefined;
  const record = state ? oauthStates.get(state) : undefined;

  if (error) {
    response.status(400).type('html').send(`<p>LinkedIn authorization failed: ${error}</p>`);
    return;
  }

  if (!code || !state || !record) {
    response.status(400).type('html').send('<p>Missing or invalid OAuth state.</p>');
    return;
  }

  oauthStates.delete(state);

  try {
    const tokenRecord = await exchangeAuthorizationCode(code);
    await saveTokenRecord(tokenRecord);

    const redirectTarget = record.returnTo;
    if (redirectTarget) {
      response.redirect(redirectTarget);
      return;
    }

    response.type('html').send(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>LinkedIn connected</title></head>
  <body>
    <h1>LinkedIn connected</h1>
    <p>Authorized as ${tokenRecord.memberName ?? tokenRecord.memberId}.</p>
    <p>You can close this tab and return to the MCP client.</p>
  </body>
</html>`);
  } catch (callbackError) {
    response.status(500).type('html').send(`<pre>${String(callbackError)}</pre>`);
  }
});

app.post('/auth/linkedin/disconnect', async (_request, response) => {
  await saveTokenRecord(null);
  response.json({ ok: true });
});

app.get('/auth/linkedin/status', async (_request, response) => {
  const record = await loadTokenRecord();
  response.json({
    connected: isTokenStillValid(record),
    memberId: record?.memberId ?? null,
    memberName: record?.memberName ?? null,
    expiresAt: record?.expiresAt ?? null
  });
});

app.get('/.well-known/oauth-protected-resource/mcp', (_request, response) => {
  response.status(404).json({ error: 'LinkedIn OAuth is managed separately from MCP transport auth.' });
});

app.use('/mcp', async (request, response, next) => {
  if (request.method === 'GET' || request.method === 'DELETE' || request.method === 'POST') {
    next();
    return;
  }

  response.sendStatus(405);
});

app.post('/mcp', async (request, response) => {
  const sessionId = typeof request.header('mcp-session-id') === 'string' ? request.header('mcp-session-id') : undefined;

  try {
    let transport = sessionId ? transports.get(sessionId) : undefined;

    if (!transport && isInitializeRequest(request.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (initializedSessionId: string) => {
          transports.set(initializedSessionId, transport!);
        }
      });

      transport.onclose = () => {
        const currentSessionId = transport?.sessionId;
        if (currentSessionId) {
          transports.delete(currentSessionId);
        }
      };

      await createServer().connect(transport);
      await transport.handleRequest(request, response, request.body);
      return;
    }

    if (!transport && sessionId) {
      response.status(404).json({
        jsonrpc: '2.0',
        error: { code: -32_001, message: 'Session not found' },
        id: null
      });
      return;
    }

    if (!transport) {
      response.status(400).json({
        jsonrpc: '2.0',
        error: { code: -32_000, message: 'Session ID required for non-initialize MCP requests' },
        id: null
      });
      return;
    }

    await transport.handleRequest(request, response, request.body);
  } catch (error) {
    if (!response.headersSent) {
      response.status(500).json({
        jsonrpc: '2.0',
        error: { code: -32_603, message: String(error) },
        id: null
      });
    }
  }
});

app.get('/mcp', async (request, response) => {
  const sessionId = typeof request.header('mcp-session-id') === 'string' ? request.header('mcp-session-id') : undefined;
  const transport = sessionId ? transports.get(sessionId) : undefined;

  if (!transport) {
    response.status(404).send('Session not found');
    return;
  }

  await transport.handleRequest(request, response);
});

app.delete('/mcp', async (request, response) => {
  const sessionId = typeof request.header('mcp-session-id') === 'string' ? request.header('mcp-session-id') : undefined;
  const transport = sessionId ? transports.get(sessionId) : undefined;

  if (!transport) {
    response.status(404).send('Session not found');
    return;
  }

  await transport.handleRequest(request, response);
});

app.listen(port, host, () => {
  console.log(`LinkedIn MCP server listening on http://${host}:${port}`);
  console.log(`MCP endpoint: ${baseUrl}/mcp`);
  console.log(`OAuth callback: ${linkedinRedirectUri}`);
});
