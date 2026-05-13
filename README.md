# LinkedIn MCP Server

This is an MCP server that exposes a small HTTP API for connecting a LinkedIn account and posting updates on behalf of that account.

It uses LinkedIn's OAuth 2.0 authorization code flow. LinkedIn does not support a username/password API login for this use case, so the server must send the member through the browser-based OAuth consent flow.

## Environment variables

- Copy [.env.example](.env.example) as a starting point for local or deployment configuration.

- `API_KEY` - (optional) Bearer token required for MCP requests. If set, all requests to `/mcp` must include `Authorization: Bearer <API_KEY>` header. Leave unset to allow unauthenticated access.
- `LINKEDIN_CLIENT_ID` - LinkedIn app client id.
- `LINKEDIN_CLIENT_SECRET` - LinkedIn app client secret.
- `LINKEDIN_REDIRECT_URI` - absolute HTTPS callback URL registered in LinkedIn.
- `BASE_URL` - public base URL for the deployment, used for links returned by tools.
- `PORT` - HTTP port, defaults to `3000`.
- `HOST` - bind host, defaults to `0.0.0.0`.
- `LINKEDIN_SCOPES` - OAuth scopes to request, defaults to `r_liteprofile w_member_social`.
- `LINKEDIN_TOKEN_STORE` - file path used to persist the LinkedIn token, defaults to `/data/linkedin-token.json`.

## Local run

```bash
npm install
npm run dev
```

Open the root page or `GET /auth/linkedin/start` to begin the LinkedIn authorization flow.

## MCP tools

- `linkedin_connection_status` - check whether a token is stored.
- `linkedin_connect` - return the LinkedIn authorization URL.
- `linkedin_post` - create a LinkedIn post for the connected member.

## Deploying with Docker

Build and run the image with your LinkedIn app credentials and a persistent volume for `/data`.

The callback URL you register in LinkedIn must exactly match `LINKEDIN_REDIRECT_URI`.
