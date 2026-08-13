import { readFileSync, existsSync } from "node:fs";
import { inflateSync } from "node:zlib";
import { describe, expect, it } from "vitest";

/**
 * Alpha of the top-left pixel — the corner a plate fills and a bare mark leaves
 * empty. Row 0 needs no un-filtering: every PNG filter predicts the first pixel
 * from neighbours that are all zero above and left of it, so the stored bytes
 * are the raw ones whichever filter the encoder picked.
 */
function cornerAlpha(file: string): number {
  const buf = readFileSync(file);
  expect(buf.subarray(1, 4).toString("ascii"), `${file} is not a PNG`).toBe("PNG");
  const bitDepth = buf[24];
  const colorType = buf[25];
  expect(bitDepth, `${file}: expected 8-bit`).toBe(8);
  // 2 = truecolour, 6 = truecolour+alpha. An encoder drops the alpha channel
  // when every pixel is opaque, so colour type 2 IS the answer: no transparency
  // anywhere in the file.
  expect([2, 6], `${file}: unexpected colour type ${colorType}`).toContain(colorType);
  if (colorType === 2) return 255;

  const idat: Buffer[] = [];
  for (let off = 8; off + 8 <= buf.length; ) {
    const len = buf.readUInt32BE(off);
    const type = buf.subarray(off + 4, off + 8).toString("ascii");
    if (type === "IDAT") idat.push(buf.subarray(off + 8, off + 8 + len));
    if (type === "IEND") break;
    off += 12 + len;
  }
  return inflateSync(Buffer.concat(idat))[4]; // [0] is the row filter, then R,G,B,A
}

/**
 * The tab icon must ship, must be legible on both tab strips, and must be the
 * SAME mark everywhere.
 *
 * Two separate failures got us here. First, neither SVG existed in web/public,
 * so nginx answered /favicon.svg from the SPA catch-all with index.html
 * (content-type text/html); the browser discarded it and fell back, which is
 * why a dark tile stayed put in light mode — the swap was between two URLs that
 * both returned HTML.
 *
 * Second, once they shipped, the variants disagreed about the ARTWORK, not just
 * the ink: four of the six carried a filled plate (near-black, or white with a
 * hairline) and two did not. Open the console, the Keycloak login and the admin
 * console at once and the same product showed three different tab icons. The
 * mark is now tile-less everywhere and the plate is what these tests forbid.
 */

/** Every favicon this repo ships, relative to web/. */
const SHIPPED = [
  "public/favicon.svg",
  "public/favicon-light.svg",
  "../engine/internal/api/favicon.svg",
  "../engine/internal/api/favicon-light.svg",
  "../scripts/deploy/keycloak-theme/ebpf-soc/login/resources/img/favicon.svg",
  "../scripts/deploy/keycloak-theme/ebpf-soc/login/resources/img/favicon-light.svg",
  "../scripts/deploy/keycloak-theme/ebpf-soc/account/resources/img/favicon.svg",
  "../scripts/deploy/keycloak-theme/ebpf-soc/admin/resources/img/favicon.svg",
];

describe("favicon assets ship with the bundle", () => {
  it("every variant exists", () => {
    for (const f of SHIPPED) expect(existsSync(f), `${f} missing`).toBe(true);
  });

  it("they are actually SVG, not an HTML fallback", () => {
    for (const f of SHIPPED) {
      const body = readFileSync(f, "utf8");
      expect(body, `${f} is not SVG`).toMatch(/^<svg[\s>]|^<\?xml/);
      expect(body).not.toMatch(/<!doctype html>/i);
    }
  });
});

describe("one mark, no tile", () => {
  it("no variant paints a plate behind the mark", () => {
    // A <rect> spanning the viewBox IS the tile. Whatever colour it is, it
    // stops the icon inheriting the strip it lands on, and it is the only
    // reason the console and Keycloak tabs ever looked like different products.
    for (const f of SHIPPED) {
      const body = readFileSync(f, "utf8");
      expect(body, `${f} still paints a tile`).not.toMatch(/<rect/);
      expect(body, `${f} keeps the old dark plate ink`).not.toMatch(/#0a0f1c/);
    }
  });

  it("every variant draws the identical geometry", () => {
    const geometry = (body: string) => [...body.matchAll(/\sd="([^"]+)"/g)].map((m) => m[1]);
    const want = geometry(readFileSync("public/favicon.svg", "utf8"));
    expect(want.length, "the mark should be two hex paths").toBe(2);
    for (const f of SHIPPED) {
      expect(geometry(readFileSync(f, "utf8")), `${f} drew a different mark`).toEqual(want);
    }
  });
});

describe("the raster set carries no tile either", () => {
  // The SVGs were only half the icons. apple-touch-icon and the three PWA
  // icons are PNGs with the plate baked in as PIXELS, so every SVG fix left
  // them untouched — and they are what Safari, the manifest and an installed
  // app window actually display. Two rounds of "the tile is still there" were
  // this raster set, not the vector one.
  it("the icons that land on an unknown surface are transparent", () => {
    for (const f of ["public/apple-touch-icon.png", "public/pwa-192x192.png", "public/pwa-512x512.png"]) {
      expect(cornerAlpha(f), `${f} still paints a plate`).toBe(0);
    }
  });

  it("the maskable icon stays opaque, because the launcher crops it", () => {
    // The one deliberate exception: a maskable icon is masked to the platform's
    // own shape, so a transparent plate leaves the mark floating on whatever
    // the launcher paints under it. This is not the tab icon and never was.
    expect(cornerAlpha("public/pwa-maskable-512x512.png")).toBe(255);
  });
});

describe("the /favicon.ico slot answers with an actual icon", () => {
  // Browsers request /favicon.ico by convention even when a <link> names an
  // SVG, and vertical tab strips, bookmark bars and history lists often prefer
  // it. The console shipped no such file, so nginx answered from the SPA
  // catch-all with index.html and the browser discarded it; the engine answered
  // with SVG bytes under image/svg+xml, unusable to anything that trusts the
  // extension. Both fell back to whatever icon was already cached.
  const ico = "public/favicon.ico";

  it("ships, and is a real ICO", () => {
    expect(existsSync(ico), "public/favicon.ico missing").toBe(true);
    const buf = readFileSync(ico);
    expect(buf.readUInt16LE(0), "not an ICO header").toBe(0);
    expect(buf.readUInt16LE(2), "not an ICO header").toBe(1);
    expect(buf.readUInt16LE(4), "expected 16/32/48 entries").toBe(3);
  });

  it("carries alpha, so it has no plate either", () => {
    const buf = readFileSync(ico);
    const off = buf.readUInt32LE(6 + 12); // first directory entry's data offset
    const bitCount = buf.readUInt16LE(off + 14); // BITMAPINFOHEADER.biBitCount
    expect(bitCount, "expected 32bpp BGRA").toBe(32);
    // Pixel data follows the 40-byte header, bottom-up: the first stored pixel
    // is the bottom-left corner, which a plate would fill and the mark leaves
    // empty.
    expect(buf[off + 40 + 3], "the ICO paints a plate").toBe(0);
  });
});

describe("ink stays legible on the strip it lands on", () => {
  it("the light variant uses ink that holds up on white", () => {
    // #22d3ee on white is ~1.9:1 — invisible at 16px. The light variant must
    // use the deeper cyan.
    for (const f of SHIPPED.filter((f) => f.includes("-light"))) {
      const body = readFileSync(f, "utf8");
      expect(body, `${f} is not the deep cyan`).toMatch(/#0891b2/);
      expect(body, `${f} uses the dark-strip cyan on white`).not.toMatch(/#22d3ee/);
    }
  });

  it("the default variant adapts on its own, for pages that run no JS", () => {
    for (const f of SHIPPED.filter((f) => !f.includes("-light"))) {
      const body = readFileSync(f, "utf8");
      expect(body, `${f} cannot follow the OS theme`).toMatch(/prefers-color-scheme:\s*light/);
      // Chromium ignores that query in a favicon, so whatever it falls back to
      // has to work on BOTH strips. The mid-cyan does; neither extreme does.
      expect(body, `${f} defaults to an ink that only works on one strip`).toMatch(
        /\.mark\s*{\s*stroke:\s*#0aa5c4/,
      );
    }
  });
});

describe("the swap cannot point at a URL that does not exist", () => {
  it("the referenced filenames match what applyTheme swaps to", () => {
    const theme = readFileSync("src/lib/theme.ts", "utf8");
    expect(theme).toMatch(/favicon-light\.svg/);
    expect(theme).toMatch(/favicon\.svg/);
  });

  it("the console and Keycloak cache-busters agree", () => {
    // Both stores are keyed by URL, so a changed artwork that keeps its version
    // is a change no returning browser ever sees. They are bumped together or
    // one surface silently keeps the old icon.
    const theme = readFileSync("src/lib/theme.ts", "utf8");
    const js = readFileSync(
      "../scripts/deploy/keycloak-theme/ebpf-soc/login/resources/js/favicon.js",
      "utf8",
    );
    const consoleV = theme.match(/FAVICON_V\s*=\s*"(\d+)"/)?.[1];
    const keycloakV = js.match(/var V\s*=\s*"(\d+)"/)?.[1];
    expect(consoleV, "FAVICON_V not found").toBeDefined();
    expect(keycloakV, "favicon.js V not found").toBeDefined();
    expect(keycloakV).toBe(consoleV);
  });

  it("every hardcoded favicon URL carries the current version", () => {
    // The version is not one constant — it is stamped into the <link> of every
    // entry HTML and into the theme-swap line of the legacy standalone pages,
    // 13 sites across 10 files, plus FAVICON_V and the Keycloak script. Bumping
    // only the two constants changes nothing a browser ever sees: the FIRST
    // icon it fetches is the one in the <link>, and if that URL is unchanged
    // the favicon store answers from cache and the swap never gets a look in.
    // That is exactly how a corrected artwork shipped and looked identical.
    const theme = readFileSync("src/lib/theme.ts", "utf8");
    const want = theme.match(/FAVICON_V\s*=\s*"(\d+)"/)?.[1];
    expect(want, "FAVICON_V not found").toBeDefined();

    // The Vite entries are the only shipped pages. The engine used to embed five
    // standalone HTML consoles alongside these and they were checked here too —
    // they have since been deleted as unreachable (nothing routed to them; /login
    // is served from this bundle), so there is one set of pages again.
    const pages = ["index.html", "login.html", "choke.html", "fleet.html", "devices.html"];

    for (const p of pages) {
      const body = readFileSync(p, "utf8");
      const urls = [...body.matchAll(/\/favicon(?:-light)?\.svg(\?v=(\d+))?/g)];
      expect(urls.length, `${p} references no favicon`).toBeGreaterThan(0);
      for (const [url, , v] of urls) {
        expect(v, `${p}: ${url} has no cache-buster; it will never refresh`).toBeDefined();
        expect(v, `${p}: ${url} is stale against FAVICON_V=${want}`).toBe(want);
      }
    }

    // The raster set needs the same discipline: the manifest and the
    // apple-touch-icon link are the only places those URLs appear, and an
    // installed app keeps its icon until the manifest URL changes.
    for (const p of ["index.html", "login.html", "choke.html", "fleet.html", "devices.html"]) {
      const body = readFileSync(p, "utf8");
      const m = body.match(/\/apple-touch-icon\.png(\?v=(\d+))?/);
      expect(m, `${p} does not link apple-touch-icon`).not.toBeNull();
      expect(m?.[2], `${p}: apple-touch-icon is stale against FAVICON_V=${want}`).toBe(want);
    }
    const vite = readFileSync("vite.config.ts", "utf8");
    for (const [url, , v] of vite.matchAll(/\/pwa-[a-z0-9x-]+\.png(\?v=(\d+))?/g)) {
      expect(v, `vite.config.ts: ${url} has no cache-buster`).toBeDefined();
      expect(v, `vite.config.ts: ${url} is stale against FAVICON_V=${want}`).toBe(want);
    }

    // The Keycloak admin and account consoles declare their icon in
    // theme.properties, and Keycloak versions resourceUrl by the SERVER build —
    // so a theme-only change leaves the URL byte-identical and the favicon
    // store never looks again. These two need the buster most, and had none.
    for (const t of ["admin", "account"]) {
      const props = readFileSync(
        `../scripts/deploy/keycloak-theme/ebpf-soc/${t}/theme.properties`,
        "utf8",
      );
      const v = props.match(/^favIcon=.*\?v=(\d+)\s*$/m)?.[1];
      expect(v, `${t}/theme.properties favIcon has no ?v=`).toBeDefined();
      expect(v, `${t}/theme.properties is stale against FAVICON_V=${want}`).toBe(want);
    }
  });

  it("the platform-admin login theme owns no favicon to drift", () => {
    // It sets parent=ebpf-soc and inherits the icon. It used to ship its own
    // copy, which stayed on the tiled artwork long after the parent moved on —
    // and it had no favicon-light.svg at all, so the inherited swap script
    // requested a 404 in light mode and the tab fell back to a blank page icon.
    const own = "../scripts/deploy/keycloak-theme/ebpf-soc-admin/login/resources/img";
    for (const f of ["favicon.svg", "favicon.ico", "favicon-light.svg"]) {
      expect(existsSync(`${own}/${f}`), `${f} is back; it will drift from the parent`).toBe(false);
    }
  });
});
