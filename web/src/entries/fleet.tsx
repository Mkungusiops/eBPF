import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import FleetRoute from "../features/fleet/FleetRoute";
import { registerServiceWorker } from "../lib/pwa";

function bootstrapTheme() {
  try {
    const raw = localStorage.getItem("soc.theme");
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    const theme = parsed === "light" || raw === "light" ? "light" : "dark";
    document.documentElement.classList.toggle("theme-light", theme === "light");
    document.body.classList.toggle("theme-light", theme === "light");
  } catch {
    document.documentElement.classList.remove("theme-light");
  }
}

bootstrapTheme();

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
