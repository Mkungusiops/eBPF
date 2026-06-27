import { createRoot } from "react-dom/client";
import { StreamProvider } from "../../lib/stream";
import { SocRoute } from "./SocRoute";
import { SOC_PANEL_INVENTORY, SOC_STORAGE_KEYS } from "./panelInventory";

export { SocRoute, SOC_PANEL_INVENTORY, SOC_STORAGE_KEYS };

export function mountSocRoute(element: HTMLElement) {
  createRoot(element).render(
    <StreamProvider>
      <SocRoute />
    </StreamProvider>
  );
}

export default SocRoute;
