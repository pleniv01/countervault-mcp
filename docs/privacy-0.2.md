# Countervault assistant integration privacy

Effective November 11, 2026. This notice covers the Countervault MCP service and its Claude and ChatGPT plugins. It supplements the [Countervault website policy](https://api.countervault.co/privacy).

## Public receipt checks

Public verification tools receive a Countervault public receipt URL and, for comparison, a SHA-256 fingerprint. A receipt URL contains a sharing reference that can grant access to sealed metadata. The service retrieves that receipt from Countervault's API and processes its metadata, filenames, dates, fingerprints, title and context in memory to recompute the manifest. The tool result contains receipt number, integrity result, entry count, save date, reported anchor status and comparison results. It does not return original files, note text, titles or context through these public tools. The synthetic `demo` uses fictional data.

## Connected accounts and consent

Private account tools require a Countervault sign-in and explicit OAuth consent. The consent page lists read and optional write access and identifies the assistant's return origin. Do not paste passwords, sign-in links, session tokens or payment details into an assistant conversation.

Directory reviewers can use a privately supplied review code to sign in to a separate account containing fictional examples. That code grants no access to ordinary customer accounts. Its temporary browser session lasts one hour; any resulting assistant connection follows the same scopes, consent and revocation rules as other connections.

Read access lets the assistant retrieve your account/subscription status and the folders, note text, entry metadata and receipt summaries you request. Write access also permits creating private folders, saving requested notes and generating receipts. Folder permissions and subscription checks remain in force. Tool calls send requested folder IDs, titles, note text, reported event times and retry identifiers to Countervault. Notes and folders you ask to save become account records under the website's retention policy. A receipt seals existing entries and inherits the folder's visibility. The tools cannot delete records, enable sharing, invite others, request blockchain timestamps, charge a card or change a subscription. Subscription checkout and billing management happen separately on the Countervault website.

The assistant provider receives tool results, which can include personal information contained in your saved notes. Connect only an account whose relevant information you intend to use in that assistant. Countervault does not retrieve your entire chat history; it receives the arguments the assistant includes in individual tool calls. Review the content before asking to save it.

## Authentication and connector storage

Countervault issues assistant access tokens scoped to this MCP service rather than accepting an assistant's token for an unrelated service. Authorization uses one-use codes, PKCE and an exact registered callback. Access tokens expire after one hour; refresh tokens rotate and cannot extend a connection beyond 30 days without new consent. Replaying a used refresh token revokes the connection.

The connector database stores registered client metadata, short-lived authorization requests and code/token hashes, consented scope, user/account identifiers, connection lifetime and revocation state. A separately minted backend session credential is encrypted with authenticated encryption; it is not returned to the assistant. Retry records retain an operation's payload hash and result summary so repeated requests do not duplicate a save. Summaries can contain a folder/note title and receipt identifiers, but do not retain the note body or original files in the connector database. Requested note bodies are stored by the main Countervault account service when saved.

Authorization requests expire after ten minutes and codes after one minute. Housekeeping runs at startup and approximately every ten minutes to remove expired requests, codes and tokens. It removes expired connections and connections revoked for more than one day, together with their retry records and dedicated sessions. Revocation clears the encrypted session value and blocks new access immediately. Infrastructure backups may outlive deletion from the active database.

## Logs and service providers

The MCP application does not log tool arguments, receipt references, fingerprints, note bodies, tokens or response contents. Inputs and upstream responses are processed in memory; finishing a request is not a promise of immediate memory erasure. Temporary rate-limit counters retain connecting IP addresses in memory for 60-second windows; expired entries are removed on a later request or restart. An idle process may retain an expired counter until then.

Railway hosts the connector, database and Countervault API. Network, security and operational metadata may be retained under hosting settings and [Railway's privacy policy](https://railway.com/legal/privacy). Netlify hosts the Countervault sign-in/consent interface. This notice does not promise a fixed deletion deadline for provider logs or backups. MCP initialization also supplies client/protocol information; the connecting IP may belong to the assistant provider rather than your device.

Anthropic or OpenAI processes conversations, tool inputs and results under the user's account settings and their respective policies. This service does not use tool inputs to train generalized AI models, sell them or target advertising. Removing a plugin does not erase information already held in an assistant conversation.

## Your choices and contact

Countervault's **Connected AI assistants** controls let you review and revoke account connections. Revocation stops new access; it does not delete existing account records, prior assistant responses, downloaded copies or public timestamp commitments. Account records and deletion follow the website policy. You can also keep receipt verification local using a downloaded proof bundle and your own originals.

For public integration support use [GitHub Issues](https://github.com/pleniv01/countervault-claude-plugin/issues). Do not post receipt links, credentials, note text, private files or fingerprints there. Follow the website's private-contact instructions for account/privacy requests. The product is not specifically designed for children or for medical diagnosis. Material changes to this notice carry an updated date.
