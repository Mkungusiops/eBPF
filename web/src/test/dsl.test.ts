import { matchesQuery, parseQuery } from "../lib/dsl";

describe("search DSL", () => {
  it("parses bare, keyed, comparison, and negated tokens", () => {
    expect(parseQuery("cat severity:critical score>=40 !noise")).toEqual([
      { value: "cat", negated: false },
      { key: "severity", op: ":", value: "critical", negated: false },
      { key: "score", op: ">=", value: "40", negated: false },
      { value: "noise", negated: true }
    ]);
  });

  it("matches keyed tokens against record fields", () => {
    expect(matchesQuery({ process: "cat", severity: "critical" }, "process:cat severity:crit")).toBe(true);
    expect(matchesQuery({ process: "cat", severity: "critical" }, "process:bash")).toBe(false);
  });

  it("applies negated tokens to the full record haystack", () => {
    expect(matchesQuery({ process: "cat", args: "/etc/shadow" }, "cat !curl")).toBe(true);
    expect(matchesQuery({ process: "curl", args: "http://example.test" }, "!curl")).toBe(false);
  });
});
