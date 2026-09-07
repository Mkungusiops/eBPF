import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * WHAT THE NUMBERS ARE ABOUT, WHEREVER THEY ARE STAMPED.
 *
 * `msocIdentityScope.test.tsx` pins the top bar: a provider's host pill must
 * not read as one customer's name, and must say which customer is on screen.
 * That fix moved the SERVER's answer — for a cross-tenant principal whoami now
 * returns host = "all tenants" (controlplane crossTenantHost), tenants = [] and
 * viewing_tenant = the one customer every panel is actually showing.
 *
 * Three surfaces kept reading `whoami.host` and so inherited a NEW overclaim
 * from that change. Before it they printed the customer's name, which at least
 * matched the rows beside them:
 *
 *   • the executive band's "What is affected" tile — an estate-wide subject
 *     over a process count drawn from one tenant;
 *   • the assistant's scope chip — a caption on answers computed from one
 *     tenant's telemetry;
 *   • `meta.host` in the export model, which reaches the branded PDF header,
 *     the CSV summary and the Markdown block pasted into tickets.
 *
 * The last is the one that matters most and is the reason this file exists
 * separately: the scope banner cannot travel with a file. An incident report
 * headed "all tenants" whose every row belongs to one customer is read by
 * whoever it was forwarded to — the customer, an auditor — with no banner and
 * no session to correct it.
 *
 * These drive the real route and the real export studio over a stubbed
 * `fetch`, and the whoami handed to the offline surfaces is produced by the
 * real `fetchSocSnapshot` normaliser rather than hand-built. A hand-built
 * whoami would let the normaliser drop `viewing_tenant` and still pass, which
 * is the exact way the earlier sweeps stopped one layer short of the call site.
 */

// jsPDF is loaded dynamically inside the two exporters and draws to a canvas
// jsdom does not have. The fake records every `doc.text` call, which is all
// these assertions need: the header band is text, and the claim is about what
// it says.
const { FakeDoc, pdfText } = vi.hoisted(() => {
  const pdfText: string[] = [];
  class FakeDoc {
    internal = { pageSize: { getWidth: () => 595, getHeight: () => 842 } };
    setFillColor() {}
    setDrawColor() {}
    setTextColor() {}
    setFont() {}
    setFontSize() {}
    setPage() {}
    rect() {}
    roundedRect() {}
    addPage() {}
    save() {}
    getNumberOfPages() {
      return 1;
    }
    text(value: string | string[]) {
      pdfText.push(Array.isArray(value) ? value.join(" ") : String(value));
    }
  }
  return { FakeDoc, pdfText };
});

vi.mock("jspdf", () => ({ default: FakeDoc }));
vi.mock("jspdf-autotable", () => ({ default: () => {} }));

// cmdk (mounted hidden inside SocModals on every route render) observes its
// list, and jsdom has no ResizeObserver.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = globalThis.ResizeObserver ?? (NoopResizeObserver as unknown as typeof ResizeObserver);

vi.mock("../lib/stream", () => ({
  useStream: () => ({
    state: "live" as const,
    retries: 0,
    messageCount: 0,
    lastMessageAt: Date.now(),
    lastEventAt: Date.now(),
    frames: [],
    latestBatch: [],
    batchId: 0,
    reconnect: () => {}
  })
}));

// D3 owns the graph's DOM and has nothing to do with any label under test.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

const TENANT = "acme-corp";
const ESTATE_LABEL = "all tenants";

/** What the control plane answers a cross-tenant MSOC principal. */
const PROVIDER_WHOAMI = {
  user: "msoc@provider",
  host: ESTATE_LABEL,
  role: "msoc-admin",
  cross_tenant: true,
  tenants: [],
  viewing_tenant: TENANT,
  can_respond: true,
  policy_scope: "fleet"
};

/** And what it answers that customer's own analyst. Nothing here may change. */
const ANALYST_WHOAMI = {
  user: "analyst@acme",
  host: TENANT,
  role: "tenant-analyst",
  cross_tenant: false,
  tenants: [TENANT],
  viewing_tenant: TENANT,
  can_respond: true,
  policy_scope: "fleet"
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

/** Serve one whoami document, an enabled assistant, and empty everything else. */
function stubEstate(whoami: Record<string, unknown>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.startsWith("/api/whoami")) return jsonResponse(whoami);
      // The nav only offers the assistant on a deployment that has one, so the
      // scope-chip test cannot open it without this.
      if (path.startsWith("/api/assistant/chats")) return jsonResponse([]);
      if (path.startsWith("/api/assistant")) return jsonResponse({ enabled: true });
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) return jsonResponse({});
      return jsonResponse([]);
    })
  );
}

/**
 * A whoami that has been through the REAL wire normaliser, for the surfaces
 * that take one as a prop. `SocWhoami` does not declare cross_tenant or
 * viewing_tenant — socIdentityOf reconciles that — so casting a literal here
 * would assert about a shape the server never produces.
 */
async function normalizedWhoami(document: Record<string, unknown>) {
  stubEstate(document);
  const { fetchSocSnapshot } = await import("../features/soc/api");
  const read = await fetchSocSnapshot();
  return read.snapshot.whoami;
}

/** Render the route and wait for the first real whoami to land. */
async function renderRoute(): Promise<void> {
  const { SocRoute } = await import("../features/soc/SocRoute");
  render(<SocRoute />);
  await waitFor(() => {
    const pill = document.querySelector(".soc-host-pill");
    expect(pill, "the top bar never rendered a host pill").not.toBeNull();
    expect(pill!.textContent, "whoami never landed").not.toContain("localhost");
  });
}

/** The briefing tile bodies, keyed by their label. */
function briefingTile(label: string): HTMLElement {
  const sections = [...document.querySelectorAll(".soc-briefing-item")] as HTMLElement[];
  const found = sections.find((section) => section.querySelector("span")?.textContent === label);
  expect(found, `the briefing has no "${label}" tile`).toBeTruthy();
  return found!;
}

beforeEach(() => {
  window.localStorage.clear();
  // The band's briefing grid is where "What is affected" is rendered, and it is
  // collapsed by default.
  window.localStorage.setItem("soc.briefingMode", "true");
  pdfText.length = 0;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the executive band's subject is the tenant whose rows it counts", () => {
  it("names the viewed customer, not the provider's whole reach", async () => {
    stubEstate(PROVIDER_WHOAMI);
    await renderRoute();

    const tile = briefingTile("What is affected");
    const subject = tile.querySelector("strong")?.textContent?.trim();
    expect(
      subject,
      'the tile headed a one-tenant process count "all tenants" — an estate-wide claim over one customer'
    ).not.toBe(ESTATE_LABEL);
    expect(subject, "the tile does not say whose estate the processes were counted on").toBe(TENANT);

    // The account's reach is true and must survive — just not as the subject.
    expect(
      tile.querySelector("p")?.textContent,
      "the provider is not told that the count covers one customer of several"
    ).toContain("more than one customer");
  });

  it("leaves a tenant-bound operator's band exactly as it was", async () => {
    stubEstate(ANALYST_WHOAMI);
    await renderRoute();

    const tile = briefingTile("What is affected");
    expect(tile.querySelector("strong")?.textContent?.trim()).toBe(TENANT);
    expect(
      tile.querySelector("p")?.textContent,
      "an analyst who belongs to this tenant was told they are the provider"
    ).not.toContain("more than one customer");
  });
});

describe("the assistant's scope chip captions the answers it sits beside", () => {
  it("names the tenant the assistant's telemetry comes from", async () => {
    stubEstate(PROVIDER_WHOAMI);
    const { AssistantChatProvider } = await import("../features/assistant/AssistantChatProvider");
    const { SocRoute } = await import("../features/soc/SocRoute");
    render(
      <AssistantChatProvider>
        <SocRoute />
      </AssistantChatProvider>
    );
    await waitFor(() => {
      expect(document.querySelector(".soc-host-pill")?.textContent, "whoami never landed").not.toContain("localhost");
    });
    // The nav entry only appears once /api/assistant says this deployment has
    // one, so waiting for it is also what proves the probe resolved.
    const open = await screen.findByRole("button", { name: "Assistant" });
    fireEvent.click(open);

    const chip = await waitFor(() => {
      const found = document.querySelector(".chat__scope");
      expect(found, "the assistant opened without a scope chip").not.toBeNull();
      return found!;
    });
    expect(
      chip.textContent,
      'the chip claimed "all tenants" over answers drawn from one tenant\'s telemetry'
    ).not.toContain(ESTATE_LABEL);
    expect(chip.textContent?.trim()).toBe(TENANT);
  });
});

describe("the host popover names the tenant its endpoint reads resolve to", () => {
  it("keeps the estate identity and adds the customer on screen", async () => {
    stubEstate(PROVIDER_WHOAMI);
    await renderRoute();

    fireEvent.click(document.querySelector(".soc-host-pill") as HTMLElement);
    const popover = await waitFor(() => {
      const found = document.querySelector(".soc-popover-kv");
      expect(found, "the host popover did not open").not.toBeNull();
      return found!;
    });
    expect(popover.textContent, "the identity row is gone — the pill and its popover must agree").toContain(ESTATE_LABEL);
    expect(
      popover.textContent,
      "the popover lists per-endpoint reads of one customer under an estate-wide heading and never names them"
    ).toContain(TENANT);
  });
});

describe("an exported report states whose estate it describes", () => {
  async function renderStudio(document: Record<string, unknown>) {
    const whoami = await normalizedWhoami(document);
    const { ExportStudioBody } = await import("../features/soc/exportStudio");
    return render(
      <ExportStudioBody
        filteredAlerts={[]}
        rangeAlerts={[]}
        events={[]}
        decisions={[]}
        policies={[]}
        mitreRows={[]}
        whoami={whoami}
        version={{ sha: "test", labMode: false }}
      />
    );
  }

  it("stamps the viewed tenant in the metadata the file carries", async () => {
    const { container } = await renderStudio(PROVIDER_WHOAMI);
    const meta = container.querySelector(".soc-export-preview-meta")?.textContent ?? "";
    expect(meta, "the export is stamped with the provider's whole reach").not.toContain(ESTATE_LABEL);
    expect(meta, "the export does not say whose rows it carries").toContain(TENANT);
    // The reach is still recorded, against the ACCOUNT, where it cannot be read
    // as the subject of the numbers.
    expect(meta, "the file no longer says the operator was a cross-tenant account").toContain("cross-tenant account");
  });

  it("heads the branded PDF with that tenant", async () => {
    await renderStudio(PROVIDER_WHOAMI);
    fireEvent.click(screen.getByRole("button", { name: /Export PDF/ }));

    const header = await waitFor(() => {
      const line = pdfText.find((text) => text.includes("Generated"));
      expect(line, "the PDF never drew its header band").toBeTruthy();
      return line!;
    });
    expect(
      header,
      'a provider\'s incident report was headed "all tenants" while every row in it belongs to one customer'
    ).not.toContain(ESTATE_LABEL);
    expect(header, "the report header does not name the estate it covers").toContain(TENANT);
  });

  it("says the same thing in the Markdown block pasted into tickets", async () => {
    const writeText = vi.fn(async (_text: string) => {});
    Object.defineProperty(window.navigator, "clipboard", { value: { writeText }, configurable: true });
    await renderStudio(PROVIDER_WHOAMI);
    fireEvent.click(screen.getByRole("button", { name: /Copy summary/ }));

    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const summary = String(writeText.mock.calls[0][0]);
    expect(summary, "the ticket summary claims the whole estate").not.toContain(ESTATE_LABEL);
    expect(summary, "the ticket summary does not name the customer").toContain(TENANT);
  });

  it("leaves a tenant-bound analyst's export unchanged", async () => {
    const { container } = await renderStudio(ANALYST_WHOAMI);
    const meta = container.querySelector(".soc-export-preview-meta")?.textContent ?? "";
    expect(meta).toContain(TENANT);
    expect(meta, "an analyst's own export was labelled a provider artefact").not.toContain("cross-tenant account");
  });
});

describe("the ATT&CK coverage PDF states whose estate it describes", () => {
  async function headerFor(document: Record<string, unknown>): Promise<string> {
    const whoami = await normalizedWhoami(document);
    const { downloadMitrePdf } = await import("../features/soc/pdf");
    await downloadMitrePdf([], [], [], whoami);
    const line = pdfText.find((text) => text.includes("Generated"));
    expect(line, "the coverage PDF never drew its header band").toBeTruthy();
    return line!;
  }

  it("heads the report with the tenant its coverage was measured on", async () => {
    const header = await headerFor(PROVIDER_WHOAMI);
    expect(
      header,
      'the coverage report was headed "all tenants" over one customer\'s detections'
    ).not.toContain(ESTATE_LABEL);
    expect(header, "the coverage report does not name the estate it covers").toContain(TENANT);
    expect(header, "the account's reach is no longer recorded anywhere on the artefact").toContain("cross-tenant account");
  });

  it("heads a tenant-bound analyst's report exactly as before", async () => {
    const header = await headerFor(ANALYST_WHOAMI);
    expect(header).toContain(TENANT);
    expect(header).toContain("analyst@acme");
    expect(header, "an analyst's own report was labelled a provider artefact").not.toContain("cross-tenant account");
  });
});
