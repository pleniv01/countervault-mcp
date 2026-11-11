# Countervault account and verification MCP service

Account-connected record workflows and public receipt verification for Countervault. The installable Claude
plugin is maintained separately at https://github.com/pleniv01/countervault-claude-plugin.
The ChatGPT candidate is in the owner's `codex-business-plugins` collection.

Run `npm ci`, `npm test`, then `npm start` (port 3000 or `PORT`). The service
provides eight tools over stateless Streamable HTTP at `/mcp`, public documentation, privacy,
health and a clearly labeled synthetic demo. Public checks require no account. The account layer uses PostgreSQL and an
OAuth encryption key, with consented read/write scopes and existing API permissions. `OPENAI_DOMAIN_CHALLENGE` is an optional
portal-issued domain verification value, not an account credential.

`node scripts/check-live.mjs` checks both deployed tools using synthetic data.
Tests cover fixed-host fetches, manifest integrity, matches/misses, access
failures and actual MCP transport. The manifest formats were also compared with
the application implementation for receipt versions 1, 2 and 3 on November 11.

Production: https://countervault-mcp-production.up.railway.app/mcp

The service does not change Countervault account records or its application
deployment. Public checks use fixed-host GET requests; connected account tools use the
existing Countervault account APIs with a separately minted encrypted session.
Subscriptions and folder permissions are enforced by those APIs. The integration
does not change sharing, delete records, collect payment or request timestamps. See [privacy](PRIVACY.md) for data handling and infrastructure limits.
