import { renderApp } from "../app/render";
import { ChokePage } from "../features/choke/ChokePage";
import { StreamProvider } from "../lib/stream";

renderApp(
  <StreamProvider>
    <ChokePage />
  </StreamProvider>,
  "the choke gateway"
);
