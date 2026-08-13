import { classifyAlert, riskScore, severityOf } from "../lib/classify";
import type { Alert } from "../lib/types";

describe("alert classification", () => {
  it("normalizes unknown severities to info", () => {
    expect(severityOf({ severity: "unexpected" } as Alert)).toBe("info");
  });

  it("classifies credential and exfiltration language as attacks", () => {
    expect(classifyAlert({ policy_name: "override-credential-read", binary: "cat" } as Alert)).toBe("attack");
    expect(classifyAlert({ message: "possible data exfil detected" } as Alert)).toBe("attack");
  });

  it("classifies high score or severity alerts as threats", () => {
    expect(classifyAlert({ severity: "high", binary: "bash" } as Alert)).toBe("threat");
    expect(classifyAlert({ score: 25, binary: "python" } as Alert)).toBe("threat");
  });

  it("caps aggregate risk score at 100", () => {
    const alerts = Array.from({ length: 20 }, () => ({ severity: "critical" }) as Alert);

    expect(riskScore(alerts)).toBe(100);
  });
});
