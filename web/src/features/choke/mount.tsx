import React from "react";
import { createRoot } from "react-dom/client";
import { StreamProvider } from "../../lib/stream";
import { ChokeRoute } from "./ChokeRoute";

export function mountChokeRoute(target: HTMLElement = document.getElementById("root") as HTMLElement): void {
  if (!target) {
    throw new Error("mountChokeRoute: target element is required");
  }
  createRoot(target).render(
    <StreamProvider>
      <ChokeRoute />
    </StreamProvider>
  );
}
