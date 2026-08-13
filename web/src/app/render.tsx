import React from "react";
import { createRoot } from "react-dom/client";
import { registerServiceWorker } from "../lib/pwa";
import "../styles.css";

export function renderApp(node: React.ReactNode) {
  const root = document.getElementById("root");
  if (!root) throw new Error("missing #root");
  createRoot(root).render(<React.StrictMode>{node}</React.StrictMode>);
  registerServiceWorker();
}
