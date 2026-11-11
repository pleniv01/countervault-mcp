"""Render the authored privacy notice and connector documentation."""
from pathlib import Path
import html
import re

root = Path(__file__).resolve().parents[1]
public = root / 'public'
public.mkdir(exist_ok=True)
source = (root / 'PRIVACY.md').read_text()
body = []
for block in source.strip().split('\n\n'):
    content = html.escape(block)
    content = re.sub(r'\[([^\]]+)\]\((https://[^)]+)\)', r'<a href="\2">\1</a>', content)
    if content.startswith('## '):
        body.append('<h2>' + content[3:] + '</h2>')
    elif content.startswith('# '):
        body.append('<h1>' + content[2:] + '</h1>')
    else:
        body.append('<p>' + content + '</p>')
style = 'body{font:17px/1.65 system-ui;color:#172d34;background:#f5f6f2;margin:0}main{max-width:820px;margin:auto;padding:36px 24px}a{color:#176474}h1{line-height:1.2}code{overflow-wrap:anywhere}'
(public / 'privacy.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Countervault connector privacy</title><style>' + style + '</style><main>' + ''.join(body) + '</main></html>')
(public / 'index.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Countervault assistant integration</title><style>''' + style + '''</style><main><h1>Keep the receipts from your assistant</h1><p>Connect your Countervault account to find saved folders, read notes, preserve requested entries and generate dated receipts. Your existing permissions and subscription still apply. Approve read and optional write access on Countervault's consent page; never paste credentials into chat.</p><p>Subscriptions are purchased and managed at <a href="https://countervault.co/?billing=required">Countervault</a>. The integration does not collect payment, delete records, change sharing or submit blockchain timestamps.</p><h2>Public verification</h2><p>You can also check a public receipt or compare a locally computed SHA-256 fingerprint without an account. The <code>demo</code> input is a clearly labeled synthetic example. A matching digest supports integrity, not truth, authorship, ownership, original creation date or notarization.</p><h2>Connection</h2><p>MCP endpoint: <code>https://countervault-mcp-production.up.railway.app/mcp</code><br>Transport: Streamable HTTP · Public checks: no sign-in · Account tools: OAuth with PKCE</p><p>Review or revoke account access in Countervault's Connected AI assistants controls. Removing access does not delete copies already returned in a chat.</p><p><a href="/privacy.html">Integration privacy</a> · <a href="https://github.com/pleniv01/countervault-claude-plugin">Documentation</a> · <a href="https://api.countervault.co/terms">Terms</a> · <a href="https://github.com/pleniv01/countervault-claude-plugin/issues">Public support</a></p></main></html>''')
print('Built public privacy and connector documentation.')
