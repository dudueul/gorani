// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * The one observable store (~40 lines, deliberately ours — Lesson 3 of the
 * course: state management is not a dependency, it is a function you can
 * read). Components subscribe and re-render; stores never touch the DOM.
 *
 * ```text
 * const count = store(0);
 * count.subscribe((n) => …);   // fires immediately and on every set
 * count.set(n + 1);            // from anywhere
 * ```
 *
 * Why not signals from Lit? Lit's context/decorators add a dependency and a
 * dialect; the vault's state is a handful of values with clear owners
 * (session, settings, files). Forty readable lines win.
 */

type Listener<T> = (value: T) => void;

export interface Store<T> {
	get(): T;
	set(value: T): void;
	subscribe(listener: Listener<T>): () => void;
}

export function store<T>(initial: T): Store<T> {
	let value = initial;
	const listeners = new Set<Listener<T>>();
	return {
		get: () => value,
		set(next: T) {
			value = next;
			for (const l of [...listeners]) l(value);
		},
		subscribe(listener: Listener<T>) {
			listeners.add(listener);
			listener(value);
			return () => listeners.delete(listener);
		},
	};
}

/** Derive one store from another (recomputed on every source change). */
export function derived<S, T>(source: Store<S>, compute: (value: S) => T): Store<T> {
	const out = store<T>(compute(source.get()));
	source.subscribe((v) => out.set(compute(v)));
	return out;
}