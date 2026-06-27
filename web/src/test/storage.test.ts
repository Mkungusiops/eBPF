import { loadJSON, removeKey, saveJSON } from "../lib/storage";

describe("typed local storage helpers", () => {
  beforeEach(() => {
    const store = createStorageStub();
    vi.stubGlobal("localStorage", store);
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: store
    });
  });

  it("loads fallback values when the key is absent or invalid", () => {
    expect(loadJSON("missing", { theme: "dark" })).toEqual({ theme: "dark" });

    localStorage.setItem("bad", "{");

    expect(loadJSON("bad", ["fallback"])).toEqual(["fallback"]);
  });

  it("saves JSON and dispatches a storage event", () => {
    const events: StorageEvent[] = [];
    window.addEventListener("storage", (event) => events.push(event));

    saveJSON("prefs", { theme: "light" });

    expect(loadJSON("prefs", { theme: "dark" })).toEqual({ theme: "light" });
    expect(events.at(-1)?.key).toBe("prefs");
    expect(events.at(-1)?.newValue).toBe(JSON.stringify({ theme: "light" }));
  });

  it("removes keys without throwing", () => {
    saveJSON("prefs", { theme: "light" });
    removeKey("prefs");

    expect(loadJSON("prefs", null)).toBeNull();
  });
});

function createStorageStub(): Storage {
  const values = new Map<string, string>();
  return {
    get length() {
      return values.size;
    },
    clear() {
      values.clear();
    },
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    key(index: number) {
      return Array.from(values.keys())[index] ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    }
  };
}
