"""Render the authored privacy notice and a small vector-based listing mark."""
from pathlib import Path
import html
import re
from PIL import Image, ImageDraw

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
(public / 'index.html').write_text('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Countervault public verification connector</title><style>''' + style + '''</style><main><h1>Countervault public verification</h1><p>Check an existing public receipt and compare a SHA-256 file fingerprint. Originals stay on your device. This read-only connector cannot access private accounts, save records, enable sharing or submit timestamps.</p><p>MCP endpoint: <code>https://countervault-mcp-production.up.railway.app/mcp</code><br>Transport: Streamable HTTP · Authentication: none</p><p>A receipt link grants access to shared metadata. Supply only links you intend to check. A matching digest supports integrity; it does not establish truth, ownership, identity or legal notarization.</p><p>The <code>demo</code> input is explicitly synthetic and does not access a customer record.</p><p><a href="/privacy.html">Connector privacy</a> · <a href="https://github.com/pleniv01/countervault-claude-plugin">Documentation and source</a> · <a href="https://api.countervault.co/terms">Terms</a> · <a href="https://api.countervault.co/about">Operator and support</a> · <a href="https://countervault.co">Countervault</a></p></main></html>''')
icon_dir = root / '.claude-plugin'
icon_dir.mkdir(exist_ok=True)
svg = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="100" fill="#17343c"/><rect x="98" y="108" width="316" height="296" rx="30" fill="none" stroke="#f3eddd" stroke-width="20"/><circle cx="266" cy="256" r="78" fill="none" stroke="#d8ab61" stroke-width="18"/><path d="M266 178v48m0 60v48m-78-78h48m60 0h48" stroke="#d8ab61" stroke-width="18"/><circle cx="266" cy="256" r="25" fill="#f3eddd"/><path d="M130 155v44m0 114v44" stroke="#f3eddd" stroke-width="16" stroke-linecap="round"/></svg>'''
(icon_dir / 'icon.svg').write_text(svg)
im = Image.new('RGB', (1024, 1024), '#17343c')
d = ImageDraw.Draw(im)
d.rounded_rectangle((196,216,828,808), radius=60, outline='#f3eddd', width=40)
d.ellipse((376,356,688,668), outline='#d8ab61', width=36)
for segment in [((532,356),(532,452)),((532,572),(532,668)),((376,512),(472,512)),((592,512),(688,512))]:
    d.line(segment, fill='#d8ab61', width=36)
d.ellipse((482,462,582,562), fill='#f3eddd')
for y in [310,626]:
    d.line(((260,y),(260,y+88)), fill='#f3eddd', width=32)
im.resize((512,512), Image.Resampling.LANCZOS).save(icon_dir / 'icon.png')
print('Built public privacy, documentation and listing icon.')
