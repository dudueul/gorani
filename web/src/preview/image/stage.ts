// Copyright 2026- Seongwoo Hong. All rights reserved.

/**
 * Zoom, pan and pinch for one picture (commit 42d, docs/PREVIEWS.md ›
 * Images), with Pointer Events — the same code for a mouse, a pen and
 * fingers:
 *
 *   wheel             zoom around the pointer (a trackpad's pinch arrives
 *                     as a wheel with Ctrl, finer)
 *   drag              pan (once zoomed past the fit)
 *   two fingers       pinch: zoom around their middle, and pan with it
 *   double click/tap  fit ↔ 100 % (or 2× for a picture smaller than the room)
 *   + − 0 1 r         zoom in, out, fit, actual pixels, turn a quarter
 *
 * The picture is sized with width and height, not a CSS scale, so an SVG
 * is redrawn sharp at every zoom; past 300 % pixels are drawn as squares
 * (an analyst zooms in to see pixels, not a blur). A picture the browser
 * does not turn for itself (a RAW preview, a TIFF page) is turned here by
 * its EXIF Orientation.
 */

/** EXIF Orientation → quarter turns clockwise, and a mirror applied first. */
const ORIENT: Record<number, [number, boolean]> = { 1: [0, false], 2: [0, true], 3: [2, false], 4: [2, true], 5: [3, true], 6: [1, false], 7: [1, true], 8: [3, false] };

export class Stage {
	readonly el: HTMLElement;
	private pic: HTMLElement | null = null;
	private nw = 0;
	private nh = 0;
	private turns = 0;
	private mirror = false;
	private scale = 1;
	private cx = 0;
	private cy = 0;
	private fitted = true;
	private pointers = new Map<number, { x: number; y: number }>();
	private pinch: { d: number; s: number; mx: number; my: number; cx: number; cy: number } | null = null;
	private lastTap = { t: 0, x: 0, y: 0 };
	/** When a double tap last toggled: the browser may follow it with a
	 * dblclick of its own, which must not toggle back. */
	private toggledAt = 0;
	/** Called whenever the scale changes (the toolbar's label). */
	onChange: () => void = () => {};

	constructor() {
		this.el = document.createElement("div");
		this.el.className = "stage";
		this.el.setAttribute("data-test", "img-stage");
		this.el.addEventListener("wheel", (e) => this.onWheel(e), { passive: false });
		this.el.addEventListener("pointerdown", (e) => this.onDown(e));
		this.el.addEventListener("pointermove", (e) => this.onMove(e));
		this.el.addEventListener("pointerup", (e) => this.onUp(e));
		this.el.addEventListener("pointercancel", (e) => this.onUp(e));
		this.el.addEventListener("dblclick", (e) => {
			if (performance.now() - this.toggledAt > 500) this.toggle(this.rel(e));
		});
		new ResizeObserver(() => this.render()).observe(this.el);
	}

	/** Show `pic`, `w`×`h` as it is drawn, turned by `orientation` (1: as is). */
	show(pic: HTMLElement, w: number, h: number, orientation = 1): void {
		this.pic?.remove();
		this.pic = pic;
		pic.classList.add("picture");
		pic.setAttribute("data-test", "img-picture");
		pic.setAttribute("draggable", "false");
		this.el.append(pic);
		this.nw = w;
		this.nh = h;
		[this.turns, this.mirror] = ORIENT[orientation] ?? [0, false];
		this.fit();
	}

	/** The size of what is shown, turned. */
	private box(): [number, number] {
		return this.turns % 2 ? [this.nh, this.nw] : [this.nw, this.nh];
	}

	fitScale(): number {
		const [bw, bh] = this.box();
		const W = this.el.clientWidth;
		const H = this.el.clientHeight;
		if (!bw || !bh || !W || !H) return 1;
		return Math.min(1, (W - 16) / bw, (H - 16) / bh);
	}

	now(): number {
		return this.fitted ? this.fitScale() : this.scale;
	}

	zoomed(): boolean {
		return !this.fitted && this.scale > this.fitScale() * 1.01;
	}

	fit(): void {
		this.fitted = true;
		this.cx = this.cy = 0;
		this.render();
	}

	/** Zoom to `s`, keeping the point `a` (from the stage's centre) still. */
	zoomTo(s: number, a = { x: 0, y: 0 }): void {
		const from = this.now();
		const to = Math.min(32, Math.max(Math.min(0.05, this.fitScale()), s));
		this.cx = a.x - (a.x - this.cx) * (to / from);
		this.cy = a.y - (a.y - this.cy) * (to / from);
		this.scale = to;
		this.fitted = false;
		this.render();
	}

	zoomBy(f: number, a?: { x: number; y: number }): void {
		this.zoomTo(this.now() * f, a);
	}

	turn(): void {
		this.turns = (this.turns + 1) % 4;
		this.fit();
	}

	private toggle(a: { x: number; y: number }): void {
		if (this.zoomed()) this.fit();
		else this.zoomTo(this.fitScale() < 1 ? 1 : 2, a);
	}

	private rel(e: { clientX: number; clientY: number }): { x: number; y: number } {
		const r = this.el.getBoundingClientRect();
		return { x: e.clientX - r.left - r.width / 2, y: e.clientY - r.top - r.height / 2 };
	}

	private onWheel(e: WheelEvent): void {
		if (!this.pic) return;
		e.preventDefault();
		this.zoomBy(Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0015)), this.rel(e));
	}

	private onDown(e: PointerEvent): void {
		if (!this.pic || e.button > 0) return;
		this.el.setPointerCapture(e.pointerId);
		this.pointers.set(e.pointerId, this.rel(e));
		if (this.pointers.size === 2) {
			const [p, q] = [...this.pointers.values()] as [{ x: number; y: number }, { x: number; y: number }];
			this.pinch = { d: Math.hypot(p.x - q.x, p.y - q.y) || 1, s: this.now(), mx: (p.x + q.x) / 2, my: (p.y + q.y) / 2, cx: this.cx, cy: this.cy };
		}
	}

	private onMove(e: PointerEvent): void {
		const was = this.pointers.get(e.pointerId);
		if (!was) return;
		const now = this.rel(e);
		this.pointers.set(e.pointerId, now);
		if (this.pinch && this.pointers.size >= 2) {
			const [p, q] = [...this.pointers.values()] as [{ x: number; y: number }, { x: number; y: number }];
			const k = this.pinch;
			const s = Math.min(32, Math.max(Math.min(0.05, this.fitScale()), (k.s * Math.hypot(p.x - q.x, p.y - q.y)) / k.d));
			const mx = (p.x + q.x) / 2;
			const my = (p.y + q.y) / 2;
			this.cx = mx - (k.mx - k.cx) * (s / k.s);
			this.cy = my - (k.my - k.cy) * (s / k.s);
			this.scale = s;
			this.fitted = false;
			this.render();
		} else if (this.pointers.size === 1 && this.zoomed()) {
			this.cx += now.x - was.x;
			this.cy += now.y - was.y;
			this.render();
		}
	}

	private onUp(e: PointerEvent): void {
		const at = this.pointers.get(e.pointerId);
		this.pointers.delete(e.pointerId);
		if (this.pointers.size < 2) this.pinch = null;
		// A double tap (touch: no dblclick event is promised).
		if (e.pointerType === "touch" && at && this.pointers.size === 0) {
			const t = performance.now();
			if (t - this.lastTap.t < 300 && Math.hypot(at.x - this.lastTap.x, at.y - this.lastTap.y) < 30) {
				this.toggle(at);
				this.toggledAt = t;
				this.lastTap.t = 0;
			} else this.lastTap = { t, x: at.x, y: at.y };
		}
	}

	render(): void {
		const pic = this.pic;
		if (!pic) return;
		const s = this.now();
		const [bw, bh] = this.box();
		const W = this.el.clientWidth;
		const H = this.el.clientHeight;
		// Keep the picture on the stage: centred along an axis it fits in,
		// and never panned past its own edge along one it does not.
		const room = (size: number, view: number) => Math.max(0, (size * s - view) / 2 + 8);
		this.cx = bw * s <= W ? 0 : Math.max(-room(bw, W), Math.min(room(bw, W), this.cx));
		this.cy = bh * s <= H ? 0 : Math.max(-room(bh, H), Math.min(room(bh, H), this.cy));
		pic.style.width = `${this.nw * s}px`;
		pic.style.height = `${this.nh * s}px`;
		pic.style.left = `${W / 2 + this.cx}px`;
		pic.style.top = `${H / 2 + this.cy}px`;
		pic.style.transform = `translate(-50%, -50%) rotate(${this.turns * 90}deg)${this.mirror ? " scaleX(-1)" : ""}`;
		pic.style.imageRendering = s >= 3 ? "pixelated" : "auto";
		this.el.classList.toggle("zoomed", this.zoomed());
		this.onChange();
	}
}
