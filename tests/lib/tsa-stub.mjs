// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * A timestamp authority for the suites (commit 29j): OpenSSL's own RFC 3161
 * implementation (`openssl ts -reply`), not one written here. gorani's
 * parsers — worker/src/tsa.rs, web/src/vault/timestamp.ts,
 * tools/verify-export.mjs — are then checked against tokens from an
 * independent writer, which is the only kind of check that means anything
 * for a format: a writer and a reader sharing one misreading agree.
 *
 * `makeTsa()` is the authority itself (a key, a self-signed certificate
 * with the critical timeStamping EKU, a config); `startTsaStub()` puts it
 * behind HTTP the way a real TSA answers (`application/timestamp-query` in,
 * `application/timestamp-reply` out), with `failNext(n)` for an authority
 * that is down. It listens on all interfaces: workerd refuses loopback
 * fetches, so the Worker reaches it on the LAN address (like the S3 stub).
 *
 * Needs `openssl` (1.1 or later) on the PATH.
 */

import { spawnSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

function openssl(args, cwd) {
	const r = spawnSync("openssl", args, { cwd, encoding: "buffer" });
	if (r.error) throw new Error(`openssl is needed for the timestamp suites: ${r.error.message}`);
	if (r.status !== 0) throw new Error(`openssl ${args[0]} ${args[1] ?? ""}: ${r.stderr.toString()}`);
	return r.stdout;
}

let seq = 0;

/** A TSA: `key` "rsa" (2048) or "ec" (P-256). */
export function makeTsa({ key = "rsa", name = "gorani test TSA", days = 30 } = {}) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gorani-tsa-"));
	const keyArgs = key === "ec" ? ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"] : ["-newkey", "rsa:2048"];
	openssl(["req", "-x509", ...keyArgs, "-nodes", "-keyout", "tsa.key", "-out", "tsa.crt", "-days", String(days), "-subj", `/CN=${name}`, "-addext", "extendedKeyUsage=critical,timeStamping", "-addext", "keyUsage=critical,digitalSignature"], dir);
	fs.writeFileSync(path.join(dir, "serial"), "01\n");
	fs.writeFileSync(
		path.join(dir, "tsa.cnf"),
		[
			"[tsa]",
			"default_tsa = tsa1",
			"[tsa1]",
			"serial = ./serial",
			"crypto_device = builtin",
			"signer_cert = ./tsa.crt",
			"signer_key = ./tsa.key",
			"signer_digest = sha256",
			"default_policy = 1.3.6.1.4.1.99999.1",
			"digests = sha256, sha384, sha512",
			"accuracy = secs:1",
			"ordering = no",
			"tsa_name = yes",
			"ess_cert_id_chain = no",
			"ess_cert_id_alg = sha256",
			"",
		].join("\n"),
	);
	const pem = fs.readFileSync(path.join(dir, "tsa.crt"), "utf8");
	const x509 = new X509Certificate(pem);
	const spkiDer = x509.publicKey.export({ type: "spki", format: "der" });
	const run = (name, write, args) => {
		const n = `${process.pid}-${++seq}`;
		const inFile = `${name}-${n}.in`;
		const outFile = `${name}-${n}.out`;
		fs.writeFileSync(path.join(dir, inFile), write);
		openssl([...args(inFile), "-out", outFile], dir);
		const out = fs.readFileSync(path.join(dir, outFile));
		fs.rmSync(path.join(dir, inFile), { force: true });
		fs.rmSync(path.join(dir, outFile), { force: true });
		return out;
	};
	return {
		dir,
		name,
		certPem: pem,
		certDer: x509.raw,
		/** SHA-256 of the key's SubjectPublicKeyInfo — what a lead certifies. */
		spki: createHash("sha256").update(spkiDer).digest("hex"),
		/** `openssl x509 -fingerprint -sha256`, as a TSA's own page shows it. */
		fingerprint: x509.fingerprint256,
		/** A TimeStampResp for a DER TimeStampReq — what the HTTP stub answers. */
		reply: (query) => run("q", query, (q) => ["ts", "-reply", "-config", "tsa.cnf", "-queryfile", q]),
		/** The token alone over a 32-byte imprint (hex), for tests with no server. */
		token(imprintHex) {
			const query = openssl(["ts", "-query", "-digest", imprintHex, "-sha256", "-cert"], dir);
			return run("t", query, (q) => ["ts", "-reply", "-config", "tsa.cnf", "-queryfile", q, "-token_out"]);
		},
		close: () => fs.rmSync(dir, { recursive: true, force: true }),
	};
}

export async function startTsaStub(opts = {}) {
	const tsa = makeTsa(opts);
	const requests = [];
	let failures = 0;
	const server = http.createServer((req, res) => {
		const chunks = [];
		req.on("data", (c) => chunks.push(c));
		req.on("end", () => {
			const query = Buffer.concat(chunks);
			requests.push({ at: Date.now(), contentType: req.headers["content-type"], authorization: req.headers.authorization ?? null, refused: failures > 0 });
			if (failures > 0) {
				failures--;
				res.writeHead(503, { "content-type": "text/plain" }).end("down for maintenance");
				return;
			}
			try {
				res.writeHead(200, { "content-type": "application/timestamp-reply" }).end(tsa.reply(query));
			} catch (e) {
				res.writeHead(400, { "content-type": "text/plain" }).end(String(e));
			}
		});
	});
	await new Promise((resolve) => server.listen(0, "0.0.0.0", resolve));
	const lan = Object.values(os.networkInterfaces())
		.flatMap((xs) => xs ?? [])
		.find((x) => x && !x.internal && x.family === "IPv4")?.address ?? "127.0.0.1";
	return {
		url: `http://${lan}:${server.address().port}/tsr`,
		tsa,
		requests,
		failNext(n) {
			failures = n;
		},
		close: () => new Promise((resolve) => server.close(() => (tsa.close(), resolve()))),
	};
}
