// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Areas — the stores the API addresses (commit 26; the Worker's twin is
 * worker/src/area.rs). A member's own area and a case are the same kind of
 * store; only the URL differs:
 *
 * | area | API base | GV04 `store` |
 * |---|---|---|
 * | `jinu` | `/api/v1/members/jinu` | `jinu` |
 * | `case:ir-2026-014` | `/api/v1/cases/ir-2026-014` | `case:ir-2026-014` |
 *
 * Everything below the base (`/files/list`, `/files/<id>`, `/audit`, …) is
 * the same, so code that takes an area — the files model, the rotation
 * walk, the media worker — works for both without knowing which it has.
 */

/** The area string of a case. */
export const caseArea = (caseId: string) => `case:${caseId}`;

/** The API base of an area (no trailing slash). */
export function areaPath(area: string): string {
	return area.startsWith("case:") ? `/api/v1/cases/${area.slice("case:".length)}` : `/api/v1/members/${area}`;
}
