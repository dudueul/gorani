// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * What each legacy format's reader returns (commit 42b, readers/legacy.ts):
 * the document as sections of plain paragraphs — a Word file is one
 * section, a slide deck one per slide — and the facts about it.
 */

import type { Fact } from "../host.ts";

export interface Section {
	title?: string;
	paras: string[];
	hidden?: boolean;
	notes?: string;
}

export interface Legacy {
	/** What the file IS, in words: "a Word 97–2003 document". */
	kind: string;
	sections: Section[];
	facts: Fact[];
	/** Set when nothing can be shown (a password, damage): why. */
	refused?: { title: string; why: string };
}

/** Split text into paragraphs, dropping empty ones. */
export function paragraphs(text: string): string[] {
	return text
		.split(/\n/)
		.map((p) => p.replace(/[ \t ]+$/g, ""))
		.filter((p) => p.trim());
}
