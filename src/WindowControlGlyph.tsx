type WindowControlName = "minimize" | "maximize" | "restore" | "close";

/**
 * Window caption glyphs.
 *
 * These were previously the literal characters `−`, `□` and `×` set in
 * "Segoe UI Symbol". Typographic glyphs carry their own side bearings and
 * baseline, so the three never aligned with each other, their stroke weights
 * did not match, and `□` reads as a hollow box rather than a maximise
 * control. Drawing them keeps all three on one 10x10 grid with a single
 * stroke weight, which is how the platform's own caption buttons are built.
 *
 * `shapeRendering="crispEdges"` keeps the horizontal and vertical strokes on
 * whole device pixels so they stay sharp at 100% scaling; the diagonal close
 * glyph is left antialiased.
 */
export function WindowControlGlyph({ name }: { readonly name: WindowControlName }) {
  return (
    <svg
      className="window-control-glyph"
      viewBox="0 0 10 10"
      width="10"
      height="10"
      fill="none"
      stroke="currentColor"
      strokeWidth="1"
      aria-hidden="true"
      focusable="false"
    >
      {name === "minimize" ? <path d="M0.5 5.5h9" shapeRendering="crispEdges" /> : null}
      {name === "maximize" ? <rect x="0.5" y="0.5" width="9" height="9" shapeRendering="crispEdges" /> : null}
      {name === "restore" ? (
        <>
          <rect x="0.5" y="2.5" width="7" height="7" shapeRendering="crispEdges" />
          <path d="M2.5 2.5V0.5h7v7h-2" shapeRendering="crispEdges" />
        </>
      ) : null}
      {name === "close" ? <path d="M0.7 0.7l8.6 8.6M9.3 0.7L0.7 9.3" strokeLinecap="round" /> : null}
    </svg>
  );
}

export default WindowControlGlyph;
