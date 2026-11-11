# Countervault connector and plugin privacy

Effective November 11, 2026. This notice covers the Countervault public-verification MCP service and its Claude and ChatGPT plugins. It supplements the [Countervault website policy](https://api.countervault.co/privacy).

## Requests and results

The tools receive a public Countervault receipt URL and, for comparison, a SHA-256 fingerprint. A receipt URL contains a sharing reference that can grant access to receipt metadata. Do not send private account links, credentials, original files or note text. MCP initialization also supplies client/protocol information; HTTP connections supply network metadata, including a connecting IP that may belong to the assistant provider.

The service requests the existing receipt from Countervault's API using a fixed-host HTTPS GET without account credentials or cookies. It recomputes the sealed manifest and compares a supplied fingerprint in memory. It returns receipt number, manifest result, entry count, save date, reported anchor status and comparison results. It does not return original files, note text, receipt titles or context. The underlying public API response includes sealed metadata, filenames, dates, fingerprints, title and context, which are processed to check the manifest. A public link is not evidence that all of this metadata is nonsensitive.

No private account connection, record creation, access-policy change, comparison-event write, payment or timestamp submission occurs. The `demo` input uses a clearly labeled synthetic fixture without a customer record.

## Retention and providers

The MCP application has no database, analytics or conversation storage. It does not log tool arguments, receipt references, fingerprints or response contents. It processes requests and upstream responses in memory; completing a request is not a promise of immediate memory erasure. Temporary rate-limit counters retain connecting addresses in memory for 60-second windows; expired entries are removed on the next MCP request, and all counters disappear on restart. An idle process can retain an expired counter until one of those events.

Railway hosts the connector and the Countervault API. Hosting, network and security logs may retain connection/request metadata under Railway's settings and [privacy policy](https://railway.com/legal/privacy); this notice does not establish a fixed provider deletion deadline. The connector makes GET requests to the existing API and does not change the underlying receipt's retention or sharing settings. Those records follow Countervault's website policy.

Anthropic or OpenAI processes the conversation, tool inputs and results under the user's account settings and their respective privacy policies. Disabling a connector does not erase records held by those providers. This service does not use tool inputs to train models, sell them or target advertising.

## Choices and contact

Supply only public receipt links you intend to check. You can keep verification local by using Countervault's downloadable proof bundle and your own originals. The integration does not ask for personal identifiers or financial/medical records. It is not designed specifically for children. Website visits and separately chosen account or billing features have their own data practices; the connector does not invoke them.

For support and privacy requests use the operator contact on [Countervault's About page](https://api.countervault.co/about). Do not include passwords, original private records or access credentials. Removing the plugin stops new requests, but does not revoke a receipt link or delete existing provider records. Changes to this notice will carry an updated date.
