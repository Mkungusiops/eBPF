import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AssistantChatProvider } from "../features/assistant/AssistantChatProvider";
import { SocRoute } from "../features/soc/SocRoute";
import { setSelectedTenant } from "../lib/tenantScope";

/**
 * THE ASSISTANT'S SCOPE CHIP CAPTIONS THE ANSWER BESIDE IT.
 *
 * `socScope3ArtefactSubject` pins that the chip names a customer rather than
 * the provider's estate label. This file pins WHICH customer, once a switcher
 * exists to make the two differ.
 *
 * The assistant WAS the one surface on this route the scoped funnel did not
 * reach, at either end — its client issued its own fetches, and the control
 * plane's tool loop read the console's endpoints with the asking analyst's
 * session cookie and no tenant, which authorizeRead resolved to the account's
 * DEFAULT customer. While a provider had the panels switched, the assistant
 * answered about someone else, and this file pinned the caption to the customer
 * the answer actually came from.
 *
 * Both ends were scoped on 2026-09-08: features/assistant/api.ts routes every
 * request through lib/tenantScope's rules, and controlplane/assistant.go
 * resolves the ask through the same authorizeReadAs every console read uses,
 * handing the result to the Runner — which now carries the customer and the
 * cookie in ONE value, so a caller cannot forward the session and forget whom
 * it is about.
 *
 * The claim this file makes is therefore unchanged and its EXPECTATION is
 * inverted: the chip must name the customer the assistant read. That is now the
 * customer on screen. A caption is a claim about the answer beside it, and the
 * lie it guards against — one customer's name over another's telemetry, in the
 * surface an analyst pastes into a handover — is available in either direction.
 */

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

// D3 owns the graph's DOM and has nothing to do with the chip.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

const DEFAULT_TENANT = "acme-corp";
const OTHER_TENANT = "globex";

const PROVIDER_WHOAMI = {
  user: "msoc@provider",
  host: "all tenants",
  role: "cross-tenant-responder",
  cross_tenant: true,
  tenants: [],
  viewing_tenant: DEFAULT_TENANT,
  can_respond: true
};

const ROSTER = {
  count: 2,
  source: "tenants table",
  tenants: [
    { tenant_id: DEFAULT_TENANT, agents: 2, agents_fresh: 2 },
    { tenant_id: OTHER_TENANT, display_name: "Globex", agents: 1, agents_fresh: 1 }
  ]
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

function stubEstate(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.startsWith("/api/whoami")) return jsonResponse(PROVIDER_WHOAMI);
      if (path.startsWith("/api/tenants")) return jsonResponse(ROSTER);
      // The nav only offers the assistant on a deployment that has one.
      if (path.startsWith("/api/assistant/chats")) return jsonResponse([]);
      if (path.startsWith("/api/assistant")) return jsonResponse({ enabled: true });
      if (path.startsWith("/api/version")) return jsonResponse({});
      return jsonResponse([]);
    })
  );
}

/** Open the assistant on a rendered route and return its scope chip. */
async function openChip(): Promise<HTMLElement> {
  const open = await screen.findByRole("button", { name: "Assistant" });
  fireEvent.click(open);
  return await waitFor(() => {
    const found = document.querySelector(".chat__scope") as HTMLElement | null;
    expect(found, "the assistant opened without a scope chip").not.toBeNull();
    return found!;
  });
}

async function renderConsole(): Promise<void> {
  render(
    <AssistantChatProvider>
      <SocRoute />
    </AssistantChatProvider>
  );
  await waitFor(() => {
    expect(document.querySelector(".soc-host-pill")?.textContent, "whoami never landed").not.toContain("localhost");
  });
}

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
  stubEstate();
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("the assistant's scope chip names the customer the assistant read", () => {
  it("names the customer switched to only when the assistant is answering about it", async () => {
    // Nothing selected: the panels and the assistant both resolve to the
    // server's default customer, so the chip reads exactly as it always did.
    await renderConsole();
    expect((await openChip()).textContent?.trim()).toBe(DEFAULT_TENANT);
  });

  it("names the switched-to customer, because that is now the one the assistant reads", async () => {
    // THIS CASE WAS INVERTED UNTIL 2026-09-08, and the inversion was correct
    // then. The assistant reached the estate outside the scoped funnel at both
    // ends, so a console switched to OTHER_TENANT still got answers about
    // DEFAULT_TENANT, and the chip deliberately named DEFAULT_TENANT: a caption
    // is a claim about the answer beside it, and naming the selection would
    // have put one customer's name on another's telemetry in the surface an
    // analyst pastes into a handover.
    //
    // Both ends are scoped now — features/assistant/api.ts routes through
    // lib/tenantScope, and controlplane/assistant.go resolves the ask through
    // authorizeReadAs and hands the tenant to the Runner — so keeping the
    // inversion would tell the same lie pointing the other way. The chip names
    // the customer on screen because the assistant now reads that customer.
    setSelectedTenant(OTHER_TENANT);
    await renderConsole();

    const chip = await openChip();
    expect(
      chip.textContent?.trim(),
      "the chip captioned the assistant's answers with a customer it no longer reads"
    ).toBe(OTHER_TENANT);
  });
});
