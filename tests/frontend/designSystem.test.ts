import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

/**
 * Design-system contract.
 *
 * The UI once carried six competing font stacks, 27 distinct font sizes
 * (the smallest 7.5px), 20 distinct corner radii, and 283 off-grid spacing
 * values. Nothing shared a rhythm, so nothing lined up. These tests keep
 * the tokens in `goralTokens.css` the single source of truth so that debt
 * cannot quietly rebuild itself.
 *
 * If a rule below fails, the fix is almost always to use the token rather
 * than to widen the exemption list.
 */

const srcDir = new URL("../../src/", import.meta.url);

/** Owns the raw values every other stylesheet must reference. */
const TOKEN_FILE = "goralTokens.css";

/** Ships vendored third-party @font-face rules, not application styling. */
const isVendored = (name: string) => name.startsWith("vendor");

const loadStylesheets = async (): Promise<ReadonlyArray<readonly [string, string]>> => {
  const names = (await readdir(srcDir))
    .filter((name) => name.endsWith(".css") && name !== TOKEN_FILE && !isVendored(name))
    .sort();
  return Promise.all(
    names.map(async (name) => [name, await readFile(new URL(name, srcDir), "utf8")] as const),
  );
};

/**
 * Strips comments so a documented counter-example inside a comment cannot
 * fail the rule it is documenting.
 */
const stripComments = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, "");

const collect = (css: string, pattern: RegExp): string[] =>
  [...stripComments(css).matchAll(pattern)].map((m) => m[0].trim());

test("every UI and monospace font stack resolves through the font tokens", async () => {
  const sheets = await loadStylesheets();
  const offenders: string[] = [];

  for (const [name, css] of sheets) {
    for (const decl of collect(css, /font-family:[^;}]+/g)) {
      const value = decl.slice(decl.indexOf(":") + 1).trim();
      if (value === "inherit" || /var\(--ld-font-(ui|mono)\)/.test(value)) continue;
      // The window min/max/close glyphs come from a symbol font whose
      // metrics the token stacks do not reproduce.
      if (/Segoe UI Symbol/.test(value)) continue;
      offenders.push(`${name}: ${decl}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "font stacks must be var(--ld-font-ui) or var(--ld-font-mono); a literal stack reintroduces the two-typefaces-at-once bug",
  );
});

test("no stylesheet sets a raw font-size in any unit", async () => {
  const sheets = await loadStylesheets();
  const offenders: string[] = [];

  for (const [name, css] of sheets) {
    // rem is the unit that escaped the first normalization pass: 279 of them
    // had drifted to 68 distinct values, the smallest 0.47rem (7.5px).
    for (const [, block, decl] of stripComments(css).matchAll(
      /([^{}]*)\{[^{}]*?(font-size:\s*[\d.]+(?:px|rem|em|pt|%))/g,
    )) {
      // The window caption glyphs are sized to the Windows symbol font's
      // own metrics, which the text scale does not reproduce.
      if (/\.window-controls/.test(block)) continue;
      offenders.push(`${name}: ${decl}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "font sizes must come from the type scale in goralTokens.css so tracking and line-height stay paired with the size",
  );
});

test("the type scale has no step below 12px", async () => {
  const tokens = await readFile(new URL(TOKEN_FILE, srcDir), "utf8");
  const sizes = [...stripComments(tokens).matchAll(/--ld-text-[a-z0-9]+-size:\s*([\d.]+)px/g)]
    .map((m) => Number(m[1]));

  assert.ok(sizes.length >= 10, "expected the full text-style ladder to be defined");
  const tooSmall = sizes.filter((px) => px < 12);
  assert.deepEqual(
    tooSmall,
    [],
    "12px is the floor; below it users reported having to lean into the screen to read chrome",
  );
});

test("no stylesheet sets a raw pixel border-radius", async () => {
  const sheets = await loadStylesheets();
  const offenders: string[] = [];

  for (const [name, css] of sheets) {
    for (const decl of collect(css, /border-radius:[^;}]*?[\d.]+px[^;}]*/g)) {
      if (/calc\(/.test(decl)) continue; // concentric-corner arithmetic
      offenders.push(`${name}: ${decl}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "corner radii must come from the radius scale so nested corners stay concentric",
  );
});

test("spacing stays on the grid", async () => {
  const sheets = await loadStylesheets();
  const offenders: string[] = [];
  const props = "padding|margin|gap|row-gap|column-gap|padding-inline|padding-block|margin-inline|margin-block";

  for (const [name, css] of sheets) {
    for (const decl of collect(css, new RegExp(`\\b(?:${props}):[^;}]+`, "g"))) {
      const value = decl.slice(decl.indexOf(":") + 1);
      if (/var\(|calc\(|%|auto/.test(value)) continue;
      for (const [, raw] of value.matchAll(/(-?[\d.]+)px/g)) {
        const px = Math.abs(Number(raw));
        // 1px is a hairline, not spacing.
        if (px > 1 && px % 2 !== 0) offenders.push(`${name}: ${decl.trim()}`);
      }
    }
  }

  assert.deepEqual(offenders, [], "spacing must land on the grid; odd values are what stopped the UI lining up");
});

/* ---------------------------------------------------------------------
 * Contrast.
 *
 * Light-mode --ld-text-muted once failed WCAG AA on every surface it was
 * used on (3.23-3.62:1) while being the color of the smallest text in the
 * app. Verify the ratios numerically rather than by eye.
 * ------------------------------------------------------------------- */

const parseHex = (hex: string): [number, number, number] => {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? [...h].map((c) => c + c).join("") : h;
  return [0, 2, 4].map((i) => Number.parseInt(full.slice(i, i + 2), 16)) as [number, number, number];
};

const relativeLuminance = (hex: string): number => {
  const [r, g, b] = parseHex(hex).map((channel) => {
    const c = channel / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

const contrastRatio = (a: string, b: string): number => {
  const [hi, lo] = [relativeLuminance(a), relativeLuminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

/** Reads one `--token: #value;` pair out of a specific selector block. */
const readTokens = (css: string, blockPattern: RegExp): Map<string, string> => {
  const block = stripComments(css).match(blockPattern);
  assert.ok(block, `expected to find the palette block matching ${blockPattern}`);
  const map = new Map<string, string>();
  for (const [, name, value] of block[0].matchAll(/(--ld-[a-z-]+):\s*(#[0-9a-fA-F]{3,6})\s*;/g)) {
    map.set(name, value);
  }
  return map;
};

const AA_NORMAL = 4.5;

test("every palette text color meets WCAG AA against every surface it sits on", async () => {
  // goralContrast.css is loaded after goralSkin.css and uses a higher
  // specificity selector, so it is the palette that actually renders.
  const css = await readFile(new URL("goralContrast.css", srcDir), "utf8");

  const modes = [
    ["light", /:root\[data-goral-mode="light"\]\s*\{[^}]*\}/],
    ["dark", /:root\[data-goral-mode="dark"\]\s*\{[^}]*\}/],
  ] as const;

  const surfaceTokens = [
    "--ld-bg",
    "--ld-surface",
    "--ld-surface-raised",
    "--ld-surface-muted",
    "--ld-surface-control",
  ];
  const inkTokens = ["--ld-text", "--ld-text-secondary", "--ld-text-muted"];

  const failures: string[] = [];

  for (const [mode, pattern] of modes) {
    const palette = readTokens(css, pattern);
    const surfaces = surfaceTokens
      .map((t) => [t, palette.get(t)] as const)
      .filter((pair): pair is readonly [string, string] => Boolean(pair[1]));

    assert.ok(surfaces.length >= 4, `${mode}: expected the surface ramp to be defined`);

    for (const ink of inkTokens) {
      const fg = palette.get(ink);
      assert.ok(fg, `${mode}: ${ink} must be defined`);
      for (const [surfaceName, bg] of surfaces) {
        const ratio = contrastRatio(fg, bg);
        if (ratio < AA_NORMAL) {
          failures.push(`${mode}: ${ink} (${fg}) on ${surfaceName} (${bg}) = ${ratio.toFixed(2)}:1`);
        }
      }
    }
  }

  assert.deepEqual(failures, [], "text tokens must clear 4.5:1 on every surface they are used on");
});

test("status colors meet WCAG AA on the surfaces they annotate", async () => {
  const css = await readFile(new URL("goralContrast.css", srcDir), "utf8");
  const failures: string[] = [];

  for (const [mode, pattern] of [
    ["light", /:root\[data-goral-mode="light"\]\s*\{[^}]*\}/],
    ["dark", /:root\[data-goral-mode="dark"\]\s*\{[^}]*\}/],
  ] as const) {
    const palette = readTokens(css, pattern);
    const surface = palette.get("--ld-surface");
    assert.ok(surface, `${mode}: --ld-surface must be defined`);

    for (const token of ["--ld-success", "--ld-warning", "--ld-danger", "--ld-accent", "--ld-purple"]) {
      const fg = palette.get(token);
      if (!fg) continue;
      const ratio = contrastRatio(fg, surface);
      if (ratio < AA_NORMAL) {
        failures.push(`${mode}: ${token} (${fg}) on --ld-surface (${surface}) = ${ratio.toFixed(2)}:1`);
      }
    }
  }

  assert.deepEqual(failures, [], "status colors carry meaning, so they must be readable, not just visible");
});

/* ---------------------------------------------------------------------
 * Blur performance contract.
 *
 * backdrop-filter costs blurred-area x backdrop-repaint-frequency. Over
 * static chrome the result is cached; over a streaming terminal canvas it
 * re-runs every frame. That second case is the only one that is slow, so
 * it must never appear.
 * ------------------------------------------------------------------- */

test("no blur layer is applied over the terminal canvas", async () => {
  const sheets = await loadStylesheets();
  const offenders: string[] = [];

  for (const [name, css] of sheets) {
    const body = stripComments(css);
    // Split into rule blocks and check any block that both targets the
    // terminal surface and blurs.
    for (const [, selector, decls] of body.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      if (!/backdrop-filter:\s*blur/.test(decls)) continue;
      if (/\.xterm|\.terminal-canvas|\.terminal-viewport|\.terminal-screen/.test(selector)) {
        offenders.push(`${name}: ${selector.trim()}`);
      }
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "blurring a surface that repaints every frame re-runs the blur every frame; keep glass on chrome only",
  );
});

test("blur radius stays within the documented ceiling", async () => {
  const sheets = await loadStylesheets();
  const tokens = await readFile(new URL(TOKEN_FILE, srcDir), "utf8");
  const ceiling = Number(
    stripComments(tokens).match(/--ld-blur-thick:\s*([\d.]+)px/)?.[1] ?? "0",
  );
  assert.ok(ceiling > 0, "--ld-blur-thick must define the ceiling");

  const offenders: string[] = [];
  for (const [name, css] of sheets) {
    for (const [, raw] of stripComments(css).matchAll(/backdrop-filter:\s*blur\(([\d.]+)px\)/g)) {
      if (Number(raw) > ceiling) offenders.push(`${name}: blur(${raw}px) exceeds ${ceiling}px`);
    }
  }

  assert.deepEqual(offenders, [], "blur cost grows with radius; stay at or below --ld-blur-thick");
});

/* ---------------------------------------------------------------------
 * One palette.
 *
 * Five workspaces each shipped a private beige/teal scheme with no dark
 * variant, so they rendered light-theme colours inside a dark application
 * and looked like a different product from the rest of the app. Settings
 * had already been solved by remapping its `--settings-*` layer onto
 * tokens; the rule below is that every workspace does the same.
 * ------------------------------------------------------------------- */

/** Stylesheets that own a workspace surface rather than the shared chrome. */
const WORKSPACE_SHEETS = [
  "notesScripts.css",
  "connectionLogs.css",
  "knownHosts.css",
  "serial.css",
  "localTerminal.css",
  "settingsSkin.css",
];

test("workspace palette variables resolve through app tokens", async () => {
  const offenders: string[] = [];

  for (const name of WORKSPACE_SHEETS) {
    const css = stripComments(await readFile(new URL(name, srcDir), "utf8"));
    // A local alias is fine; a local *value* is a second palette.
    for (const [, decl, value] of css.matchAll(/(--(?:ns|logs|kh|serial|settings)-[a-z-]+)\s*:\s*([^;]+);/g)) {
      if (/var\(--ld-|color-mix\([^)]*var\(--ld-/.test(value)) continue;
      offenders.push(`${name}: ${decl}: ${value.trim()}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "a workspace palette must alias app tokens; a literal here is a second palette that cannot follow the colour mode",
  );
});

test("workspace stylesheets carry no leftover literal palette", async () => {
  const failures: string[] = [];

  for (const name of WORKSPACE_SHEETS) {
    const css = stripComments(await readFile(new URL(name, srcDir), "utf8"));
    const literals: string[] = [];

    for (const line of css.split("\n")) {
      const decl = line.match(/^\s*([a-z-]+)\s*:/);
      if (!decl) continue;
      for (const [hex] of line.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
        // White ink on an accent fill stays literal: it is not a palette
        // entry, it is the contrast pair for one.
        if (/^#(fff|ffffff)$/i.test(hex) && /^color$/.test(decl[1])) continue;
        literals.push(`${hex} (${decl[1]})`);
      }
    }

    // A handful of contrast literals are expected; a palette is not.
    if (literals.length > 6) failures.push(`${name}: ${literals.length} literals — ${literals.slice(0, 5).join(", ")}…`);
  }

  assert.deepEqual(
    failures,
    [],
    "workspace colours must come from the palette so they follow light and dark mode",
  );
});

test("every workspace stylesheet participates in both colour modes", async () => {
  const offenders: string[] = [];

  for (const name of WORKSPACE_SHEETS) {
    const css = stripComments(await readFile(new URL(name, srcDir), "utf8"));
    // Either it defines its own mode-aware rules, or — the preferred shape —
    // it consumes tokens that are themselves mode-aware.
    const consumesTokens = /var\(--ld-/.test(css);
    const definesModes = /data-goral-mode|prefers-color-scheme/.test(css);
    if (!consumesTokens && !definesModes) offenders.push(name);
  }

  assert.deepEqual(
    offenders,
    [],
    "a stylesheet that neither consumes tokens nor defines mode rules is frozen in one colour mode",
  );
});

test("application chrome in styles.css has no private literal palette", async () => {
  const css = stripComments(await readFile(new URL("styles.css", srcDir), "utf8"));
  const offenders: string[] = [];
  const literal = /#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|\b(?:white|black)\b/g;

  for (const [, selectorSource, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const selector = selectorSource.trim();
    for (const [, property, value] of body.matchAll(/([\w-]+)\s*:\s*([^;{}]+);?/g)) {
      const colors = value.match(literal) ?? [];
      if (colors.length === 0) continue;

      const terminalTheme = (
        /\.xterm(?:\b|[-_])|\.terminal-container\b|\bansi(?:\b|[-_])|terminal-(?:theme|palette|swatch|preview|option)/i.test(selector)
        || (/\.terminal-pane-stage\b/.test(selector) && /--terminal-resolved-bg/.test(value))
      );
      const identityColor = (
        /\.brand-mark\b/.test(selector)
        || /\.ai-agent-menu-mark\.is-builtin/.test(selector)
        || /\.ai-provider-menu-mark\[data-provider=/.test(selector)
      );

      if (terminalTheme || identityColor) continue;
      offenders.push(`${selector}: ${property}: ${value.trim()}`);
    }
  }

  assert.deepEqual(
    offenders,
    [],
    "application chrome must consume --ld-* tokens; only terminal palettes and provider/logo identity colours stay literal",
  );
});
