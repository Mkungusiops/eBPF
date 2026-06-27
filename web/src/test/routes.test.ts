import {
  PAGE_ROUTES,
  PROTECTED_PAGE_ROUTES,
  TOTAL_PANEL_COUNT,
  VITE_HTML_ENTRIES
} from "../../e2e/support/contracts";

describe("route certification contract", () => {
  it("tracks all five redesigned routes", () => {
    expect(PAGE_ROUTES.map((route) => route.path)).toEqual([
      "/login",
      "/",
      "/choke",
      "/devices",
      "/fleet"
    ]);
  });

  it("tracks the 78-panel release scope", () => {
    expect(TOTAL_PANEL_COUNT).toBe(78);
    expect(Object.fromEntries(PAGE_ROUTES.map((route) => [route.name, route.panelCount]))).toEqual(
      {
        login: 1,
        soc: 31,
        choke: 26,
        devices: 7,
        fleet: 13
      }
    );
  });

  it("keeps route entries aligned to the expected Vite multi-entry shape", () => {
    expect(VITE_HTML_ENTRIES.map((entry) => entry.script)).toEqual([
      "/src/entries/soc.tsx",
      "/src/entries/choke.tsx",
      "/src/entries/devices.tsx",
      "/src/entries/fleet.tsx",
      "/src/entries/login.tsx"
    ]);
  });

  it("keeps only login public at the browser route level", () => {
    expect(PROTECTED_PAGE_ROUTES.map((route) => route.path)).toEqual([
      "/",
      "/choke",
      "/devices",
      "/fleet"
    ]);
  });
});
