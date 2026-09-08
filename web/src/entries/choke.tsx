import { renderApp } from "../app/render";
import { ChokePage } from "../features/choke/ChokePage";
import { StreamProvider } from "../lib/stream";

// No tenantScope option: this entry takes the shell default, which hydrates the
// selected customer before mounting and captions it above the page. Nothing on
// this route reads the roster or names a customer of its own.
renderApp(
  <StreamProvider>
    <ChokePage />
  </StreamProvider>,
  "the choke gateway"
);
