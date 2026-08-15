// Policy Workbench state. The preview endpoint is engine-LOCAL — it evaluates
// YAML against one host's tracked processes — so the control plane answers it
// with 501 and the route disables the button rather than offering one that
// always fails.
import { useState } from "react";
import { previewPolicy } from "./api";
import type { CircuitEntry, PolicyPreviewResponse } from "./types";
import { DEFAULT_POLICY, buildLivePolicy } from "./policy";

export function usePolicyWorkbench(circuits: CircuitEntry[]) {
  const [policyYaml, setPolicyYaml] = useState(DEFAULT_POLICY);
  const [policyPreview, setPolicyPreview] = useState<PolicyPreviewResponse | null>(null);
  const [policyError, setPolicyError] = useState("");
  const [policyChecking, setPolicyChecking] = useState(false);

  async function runPolicyPreview(): Promise<void> {
    setPolicyError("");
    setPolicyChecking(true);
    try {
      const response = await previewPolicy(policyYaml);
      setPolicyPreview(response);
      if (response.valid === false) setPolicyError((response.errors || []).join("; "));
    } catch (error) {
      setPolicyPreview(null);
      setPolicyError(error instanceof Error ? error.message : "preview failed");
    } finally {
      setPolicyChecking(false);
    }
  }

  // Generate a policy from the current tracked snapshot so "Preview matches"
  // produces real hits — the bundled sample targets throttled shells, which a
  // box where everything is severed will never match (looking broken).
  function insertLivePolicy(): void {
    const yaml = buildLivePolicy(circuits);
    setPolicyYaml(yaml);
    setPolicyPreview(null);
    setPolicyError("");
  }

  function insertSamplePolicy(): void {
    setPolicyYaml(DEFAULT_POLICY);
    setPolicyPreview(null);
    setPolicyError("");
  }

  return {
    policyYaml,
    setPolicyYaml,
    policyPreview,
    policyError,
    policyChecking,
    runPolicyPreview,
    insertLivePolicy,
    insertSamplePolicy,
  };
}
