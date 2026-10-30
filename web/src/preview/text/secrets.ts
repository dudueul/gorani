// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Secrets in text (commit 42f, docs/PREVIEWS.md › Text): what an incident
 * responder looks for first in a leaked config, a script, a paste — keys
 * and tokens that must be revoked. Each is named by kind and line, and
 * MASKED (its first and last four characters): the facts say a key is
 * there without spreading it further.
 *
 * Patterns are the providers' own published formats; the generic ones
 * (password = …) look for an assignment, not for a word.
 * Pure: unit:preview-facts.
 */

export interface Secret {
	kind: string;
	line: number;
	masked: string;
}

const RULES: [string, RegExp][] = [
	["a private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g],
	["an AWS access key", /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g],
	["an AWS secret key", /aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+]{40})\b/gi],
	["a GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
	["a GitLab token", /\bglpat-[A-Za-z0-9_-]{20,}\b/g],
	["a Slack token", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
	["a Slack webhook", /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g],
	["a Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
	["a Stripe secret key", /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b/g],
	["an OpenAI or Anthropic key", /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}\b/g],
	["a JSON Web Token", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
	["an Azure storage key", /AccountKey=([A-Za-z0-9+/]{80,}={0,2})/g],
	["a connection string with a password", /(?:Password|Pwd)\s*=\s*([^;'"\s]{4,})\s*;/gi],
	["a password in a setting", /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b["']?\s*[:=]\s*["']([^"'\s]{6,})["']/gi],
	["a URL with a password", /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:([^/\s:@]{3,})@[^\s/]+/gi],
];

const mask = (s: string) => (s.length <= 10 ? `${s.slice(0, 2)}…` : `${s.slice(0, 4)}…${s.slice(-4)}`);

/** Every secret found (the first 200), in order. */
export function findSecrets(text: string): Secret[] {
	const out: Secret[] = [];
	const lineAt = (() => {
		const starts = [0];
		for (let i = text.indexOf("\n"); i >= 0 && starts.length < 5_000_000; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
		return (at: number) => {
			let lo = 0;
			let hi = starts.length - 1;
			while (lo < hi) {
				const mid = (lo + hi + 1) >> 1;
				if (starts[mid]! <= at) lo = mid;
				else hi = mid - 1;
			}
			return lo + 1;
		};
	})();
	const seen = new Set<string>();
	for (const [kind, re] of RULES) {
		re.lastIndex = 0;
		for (let m = re.exec(text); m && out.length < 200; m = re.exec(text)) {
			const value = m[1] ?? m[0];
			const key = `${kind}:${value}`;
			if (seen.has(key)) continue;
			seen.add(key);
			// A placeholder is not a secret.
			if (/^(x+|\*+|\.+|changeme|password|your[_-]?\w*|<[^>]+>|\$\{[^}]+\}|%[^%]+%)$/i.test(value)) continue;
			out.push({ kind, line: lineAt(m.index), masked: kind === "a private key" ? "-----BEGIN … PRIVATE KEY-----" : mask(value) });
		}
	}
	return out.sort((a, b) => a.line - b.line);
}
