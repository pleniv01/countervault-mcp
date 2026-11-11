export const API_ORIGIN = 'https://api.countervault.co';

export class AccountApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

// Tokens are server-side credentials minted for the consented connection, never
// an arbitrary tool argument or an MCP access token passed to another API.
export async function accountRequest(sessionToken, path, { method = 'GET', body, fetcher = fetch } = {}) {
  if (!path.startsWith('/api/') || path.includes('..') || path.includes('?') || !sessionToken) throw new AccountApiError('Invalid account request.', 400);
  let response;
  try {
    response = await fetcher(API_ORIGIN + path, {
      method, redirect: 'error', signal: AbortSignal.timeout(20000),
      headers: { Accept: 'application/json', Authorization: 'Bearer ' + sessionToken, ...(body ? { 'Content-Type': 'application/json' } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  } catch { throw new AccountApiError('Countervault could not be reached. A write may have completed; inspect your folder before retrying with a new request ID.', 503); }
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 3 * 1024 * 1024) throw new AccountApiError('Account response is too large. Open Countervault to inspect it.', 413);
    chunks.push(chunk);
  }
  let data;
  try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new AccountApiError('Countervault returned an unreadable response. Inspect the account before retrying a write.', 502); }
  if (!response.ok) {
    const message = response.status === 402 ? 'An active Countervault subscription is required for this action. Open https://countervault.co/?billing=required to subscribe or manage billing. No payment was taken by the assistant.'
      : response.status === 401 ? 'Your Countervault connection has expired. Reconnect your account.'
      : response.status === 403 ? 'Your account does not have permission for this folder or action.'
      : String(data.error || 'Countervault request failed.').slice(0, 500);
    throw new AccountApiError(message, response.status);
  }
  return data;
}
