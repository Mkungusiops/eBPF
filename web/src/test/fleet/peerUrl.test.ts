import { normalizePeerUrl } from "../../features/soc/panels";

// The bug this guards: a bare "34.242.223.201" typed into the Fleet panel is a
// RELATIVE url to fetch(), so the probe resolved against the console's own
// origin and never left it. The peer then rendered DOWN while being perfectly
// healthy. Requiring a scheme makes that unrepresentable.
describe("normalizePeerUrl", () => {
  it("rejects a bare host or IP and says what is missing", () => {
    for (const bare of ["34.242.223.201", "192.168.1.10:8080", "engine.example.io"]) {
      const result = normalizePeerUrl(bare);
      expect(result.url).toBeUndefined();
      expect(result.error).toMatch(/scheme/i);
    }
  });

  it("rejects blank input", () => {
    expect(normalizePeerUrl("   ").url).toBeUndefined();
  });

  it("accepts http and https peers", () => {
    expect(normalizePeerUrl("https://engine.adanianlabs.io").url).toBe("https://engine.adanianlabs.io");
    expect(normalizePeerUrl("http://192.168.1.10:8080").url).toBe("http://192.168.1.10:8080");
  });

  it("reduces a peer to its origin so paths and trailing slashes cannot vary the key", () => {
    // Rows are keyed by url; "https://p/", "https://p" and "https://p/soc"
    // are one host and must not become three entries.
    expect(normalizePeerUrl("https://peer.example.io/").url).toBe("https://peer.example.io");
    expect(normalizePeerUrl("https://peer.example.io/soc/dashboard").url).toBe("https://peer.example.io");
    expect(normalizePeerUrl("  https://peer.example.io  ").url).toBe("https://peer.example.io");
  });

  it("rejects schemes the server-side probe would refuse anyway", () => {
    for (const bad of ["file:///etc/shadow", "ftp://host/", "javascript:alert(1)"]) {
      expect(normalizePeerUrl(bad).url).toBeUndefined();
    }
  });
});
