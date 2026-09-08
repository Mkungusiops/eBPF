import { renderApp } from "../app/render";
import { SocPage } from "../features/soc/SocPage";
import { StreamProvider } from "../lib/stream";

// "dashboard": the SOC route renders the provider banner itself, beside the
// customer switcher, so the shell only adds what that banner cannot say — that
// a remembered customer could not be confirmed and containment is being held.
// The selection is still hydrated by the shell, on this entry as on every
// other.
renderApp(
  <StreamProvider>
    <SocPage />
  </StreamProvider>,
  "the SOC console",
  { tenantScope: "dashboard" }
);
