import { renderApp } from "../app/render";
import { SocPage } from "../features/soc/SocPage";
import { StreamProvider } from "../lib/stream";

renderApp(
  <StreamProvider>
    <SocPage />
  </StreamProvider>
);
