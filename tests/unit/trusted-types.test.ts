// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * unit:trusted-types — the default policy's allow-list (web/src/lib/
 * trusted-types.ts). Under the app's CSP every string that becomes a script
 * URL passes through it; the allow-list is the entire answer to "what code
 * may this page start?", so each refusal is pinned next to its success.
 */

import assert from "node:assert/strict";
import { allowedScriptURL } from "../../web/src/lib/trusted-types.ts";

const O = "https://gorani.example.com";
const ok = (u: string, dev = false) => allowedScriptURL(u, O, dev);

// What the app really loads.
assert.equal(ok("/sw-media.js"), `${O}/sw-media.js`, "the media service worker");
assert.equal(ok(`${O}/assets/index.worker-CMA27nfg.js`), `${O}/assets/index.worker-CMA27nfg.js`, "a hashed Vite chunk (the index worker)");

// What it must never start.
assert.equal(ok("https://evil.example/sw-media.js"), null, "another origin");
assert.equal(ok("//evil.example/assets/x.js"), null, "a protocol-relative URL is another origin too");
assert.equal(ok("data:text/javascript,alert(1)"), null, "data: URLs");
assert.equal(ok("blob:https://gorani.example.com/uuid"), null, "blob: URLs (a script built from strings at runtime)");
assert.equal(ok("javascript:alert(1)"), null, "javascript: URLs");
assert.equal(ok("/sw-media.js?v=1"), null, "a query changes the identity of a script URL");
assert.equal(ok("/assets/../s.js"), null, "path tricks normalise outside the allowed set");
assert.equal(ok("/assets/sub/dir.js"), null, "only flat hashed chunks");
assert.equal(ok("/src/vault/index.worker.ts?worker_file&type=module"), null, "source paths only in `vite dev`…");
assert.equal(ok("/src/vault/index.worker.ts?worker_file&type=module", true), `${O}/src/vault/index.worker.ts?worker_file&type=module`, "…where they are the worker");

console.log("ok  trusted-types: same-origin app scripts only — no data:, blob:, javascript:, foreign or query-altered URLs");
