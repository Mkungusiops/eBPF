import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import FleetRoute from "../features/fleet/FleetRoute";
import { registerServiceWorker } from "../lib/pwa";
import { initTheme } from "../lib/theme";

// Apply the OS theme before first paint (see src/lib/theme.ts).
initTheme();

const root = document.getElementById("root");
if (!root) {
  throw new Error("Fleet route root element was not found");
}

createRoot(root).render(
  <StrictMode>
    <FleetRoute />
  </StrictMode>
);

registerServiceWorker();
