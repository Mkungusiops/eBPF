import { renderApp } from "../app/render";
import FleetRoute from "../features/fleet/FleetRoute";
import { initTheme } from "../lib/theme";

// Apply the OS theme before first paint (see src/lib/theme.ts).
initTheme();

// Goes through renderApp like every other entry rather than re-implementing
// createRoot/StrictMode/registerServiceWorker inline — that copy is how this
// route ended up outside the error boundary.
renderApp(<FleetRoute />, "the fleet view");
