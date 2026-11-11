# Countervault public verification MCP service

Read-only public receipt verification for Countervault. The installable Claude
plugin is maintained separately at https://github.com/pleniv01/countervault-claude-plugin.
The ChatGPT candidate is in the owner's `codex-business-plugins` collection.

Run `npm ci`, `npm test`, then `npm start` (port 3000 or `PORT`). The service
provides stateless Streamable HTTP at `/mcp`, public documentation, privacy,
health and a clearly labeled synthetic demo. No database, API keys or private
account connection are required. `OPENAI_DOMAIN_CHALLENGE` is an optional
portal-issued domain verification value, not an account credential.

`node scripts/check-live.mjs` checks both deployed tools using synthetic data.
Tests cover fixed-host fetches, manifest integrity, matches/misses, access
failures and actual MCP transport. The manifest formats were also compared with
the application implementation for receipt versions 1, 2 and 3 on November 11.

Production: https://countervault-mcp-production.up.railway.app/mcp

The service does not change Countervault account records or its application
deployment. It sends only fixed-host GET requests to the existing public receipt
API. See [privacy](PRIVACY.md) for data handling and infrastructure limits.
