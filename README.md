# Countervault account and verification MCP service

Account-connected record workflows and public receipt verification for Countervault. The installable Claude
plugin is maintained separately at https://github.com/pleniv01/countervault-claude-plugin.
The ChatGPT candidate is in the owner's `codex-business-plugins` collection.

Run `npm ci`, `npm test`, then `npm start` (port 3000 or `PORT`). The service
provides public verification and account tools over stateless Streamable HTTP at `/mcp`, public documentation, privacy,
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

## Phase 0 provenance contract (0.3.0 review)

Account record responses include tier=record and content_origin=user_authored (typed notes) or external (outside records). Labels describe source, not proven identity or truth; receipt hashes/formats are unchanged. save_note now requires text_origin. User-authored text can be saved verbatim; host_assistant text returns saved=false pending the dedicated interpretation-save feature. Do not relabel an approved AI draft as user-authored. No Insights runner, model provider, new scopes or agent grants are enabled. This is a paired API/MCP/package review; production publication is separate.

## Immutable versions (0.4.0 review)

get_folder shows current versions. get_record_history reads earlier versions through existing read access. For an explicitly requested user-authored note correction, save_note accepts correction_of_record_id plus correction_reason and creates a new version. Earlier text and receipt hashes remain unchanged; competing stale corrections are rejected. Existing write access, subscription, author/owner rules and allowance apply on the API. Assistant interpretation saves remain unavailable. No deployment is implied by this source update.

### Phase 0 attachment storage

Version 0.5.0 exposes live record `storage_mode` and actual `content_stored` availability, plus the shared allowance through `get_account_status`. Preserve missing fields on older results as unknown. A linked fingerprint is not a saved copy, and saved-copy availability does not establish historical custody or truth. Users attach, download and export files in Countervault's own UI; MCP adds no file-upload/download tool and never copies linked Drive/email content. Both Claude and ChatGPT use this shared server. This review branch requires the paired Phase 0 API changes and is not a production deployment.

### Explicit file versions (0.5.1 review)

The paired website adds reviewed local-file replacements under an explicitly selected current version. Existing get_folder/get_record_history contracts expose the current version and preserved history, source labels and actual saved-copy availability. No raw upload or replacement tool is added. Users select, review and confirm bytes in Countervault; old versions and receipts remain unchanged. This source branch is separate from the deployed storage 0.5.0 release.

### Transactional broker audit review

The audit integration requires the paired Countervault API schema through migration 0030. Browser approval/denial/revocation rechecks the presented person session in the write transaction; protocol token processing and cleanup use fixed server attribution. Audit failure rolls back the associated mutation. No tokens, scopes, redirects or client metadata are copied into audit headers. This is a coordinated review change, not an independently deployable update. Public tools and connection notice remain 0.6.0; Countervault's MCP apps do not run model providers. Unbound registration/request metadata and operation-cache outcomes still need separate coverage.

### Coordinated item deletion review

The deletion-aware operation cache requires paired API migration 0034. Quiesce old broker replicas at the coordinated release; do not run the former cache writer beside the new deletion endpoint. Operation creation and completion briefly lock the account, capture its deletion epoch and release all locks before an API/network call. Deletion clears result bodies and content commitments, retaining only hashed erased retry keys. An old completion cannot restore or return its cached result, and replaying an erased request never performs the write again.

Both Claude and ChatGPT retain the existing 0.6.0 tools/scopes/notice. There is no assistant deletion tool: the owner reviews deletion in Countervault. If a saved action result was erased, direct the user to review Countervault; never mint a new request ID to recreate it automatically. Previously returned conversation/export copies remain outside server erasure. This is review code, not a deployment or completion of the wider deletion package.

### Restore quarantine

Set `COUNTERVAULT_RESTORE_QUARANTINE=true` before a database restore and keep the API, MCP service and all workers stopped until the app's authenticated offline erasure replay and verification complete. MCP startup refuses quarantine before OAuth schema initialization, request cleanup or HTTP listening. In quarantine, `npm run restore:prepare` initializes only the broker schema on the explicitly configured restore database; it starts no listener or maintenance loop. Existing `DATABASE_URL` and `OAUTH_TOKEN_ENCRYPTION_KEY` secrets are required. Follow the app repository's `docs/architecture/BACKUP_RECOVERY.md`. Reconnect assistants after recovery; restored sessions and cached results are invalidated. No public tool, scope or connection notice changes.
