import { SSE_CONTRACT } from "./support/contracts";
import { expect, hasCredentials, loginByApi, test } from "./support/test";
import {
  createRafStreamBatcher,
  shouldProbeWhoami
} from "../src/lib/streamCore";
import type { StreamFrame } from "../src/lib/types";

test.describe("sse", () => {
  test("unauthenticated stream requests return the JSON 401 contract", async ({ request }) => {
    const response = await request.get(SSE_CONTRACT.endpoint, {
      failOnStatusCode: false,
      timeout: 5_000
    });

    expect(response.status()).toBe(401);
    expect(await response.json()).toEqual({
      error: "unauthorized",
      redirect: "/login"
    });
  });

  test("authenticated EventSource opens without withCredentials", async ({
    browser,
    request,
    ebpf
  }) => {
    test.skip(!hasCredentials(ebpf), "Set EBPF_E2E_USER and EBPF_E2E_PASSWORD");

    const { storageState } = await loginByApi(request, ebpf);
    const context = await browser.newContext({
      baseURL: ebpf.baseURL,
      storageState
    });
    const page = await context.newPage();
    await page.goto("/login");

    const result = await page.evaluate((endpoint) => {
      return new Promise<{ opened: boolean; withCredentials: boolean; error?: string }>(
        (resolve) => {
          const eventSource = new EventSource(endpoint);
          const timeout = window.setTimeout(() => {
            const { withCredentials } = eventSource;
            eventSource.close();
            resolve({ opened: false, withCredentials, error: "timeout" });
          }, 5_000);

          eventSource.onopen = () => {
            window.clearTimeout(timeout);
            const { withCredentials } = eventSource;
            eventSource.close();
            resolve({ opened: true, withCredentials });
          };
          eventSource.onerror = () => {
            window.clearTimeout(timeout);
            const { withCredentials } = eventSource;
            eventSource.close();
            resolve({ opened: false, withCredentials, error: "error" });
          };
        }
      );
    }, SSE_CONTRACT.endpoint);

    expect(result.withCredentials).toBe(false);
    expect(result).toMatchObject({ opened: true });

    await context.close();
  });

  test("expired sessions redirect through the shared stream provider whoami probe", async () => {
    expect(shouldProbeWhoami(1)).toBe(false);
    expect(shouldProbeWhoami(2)).toBe(false);
    expect(shouldProbeWhoami(3)).toBe(true);
  });

  test("SSE flood updates are rAF-batched and list-capped", async () => {
    const scheduled: Array<() => void> = [];
    const published: StreamFrame[][] = [];
    const batcher = createRafStreamBatcher({
      schedule: (callback) => {
        scheduled.push(callback);
        return scheduled.length;
      },
      cancel: () => undefined,
      publish: (batch) => published.push(batch)
    });

    for (let index = 0; index < 100; index += 1) {
      batcher.push({ type: "event", payload: { id: index } });
    }

    expect(scheduled).toHaveLength(1);
    scheduled[0]();
    expect(published).toHaveLength(1);
    expect(published[0]).toHaveLength(100);
  });
});
