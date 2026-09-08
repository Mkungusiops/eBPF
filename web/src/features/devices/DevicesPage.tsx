import { useMemo } from "react";

import { createDevicesApi } from "./api";
import { DevicesRoute } from "./DevicesRoute";

/**
 * The /devices entry point.
 *
 * It builds no requester of its own any more. This page used to adapt
 * RequestInit to the shared funnel here while `createDevicesApi()`'s own
 * default went straight to fetch() — two request paths for one plane, and the
 * unscoped one was what DevicesRoute fell back to whenever it was mounted
 * without an api prop. One of them naming the selected customer and the other
 * not is exactly how a device choke lands on a customer nobody chose, so there
 * is now a single funnel-routed default and this page uses it (see api.ts).
 */
export function DevicesPage() {
  const devicesApi = useMemo(() => createDevicesApi(), []);
  return <DevicesRoute api={devicesApi} />;
}
