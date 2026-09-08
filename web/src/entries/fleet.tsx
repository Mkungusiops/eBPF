import { FLEET_SURFACE_URL } from "../features/fleet/address";

/**
 * /fleet IS A REDIRECT NOW. IT IS NOT DELETED, AND IT MUST NOT BE.
 *
 * The fleet view moved into the SOC console as a surface (features/fleet/
 * FleetSurface.tsx, mounted by features/soc/SocModals.tsx). The address stayed,
 * because addresses outlive the pages behind them: operators have /fleet
 * bookmarked, the live probe suite signs in AT /fleet against the estate
 * (e2e/probe/console.probe.spec.ts), and the command palette still offers it as
 * a route. Deleting the entry would 404 all three.
 *
 * So this entry keeps its HTML shell, its build input and its server route, and
 * does exactly one thing: send the browser to the console with the fleet
 * surface named in the fragment. See features/fleet/address.ts for why a
 * fragment rather than a query parameter.
 *
 * `replace`, not `assign`: this page is a signpost, not a destination, and
 * leaving it in the history would put the operator back on the signpost every
 * time they pressed Back — a loop out of the console they just reached.
 *
 * NOTHING IS RENDERED AND NOTHING IS SET UP. No renderApp, no theme, no service
 * worker, no tenant hydration: every one of those belongs to the console this
 * navigates to, and doing them here would be a whole console boot — including a
 * roster fetch and a hydration barrier — thrown away one tick later. The
 * redirect is issued at module scope so it goes before the browser has painted
 * anything at all.
 *
 * AUTH IS UNAFFECTED. An unauthenticated GET /fleet is still answered by the
 * server with a 303 to /login exactly as before; this code only runs once the
 * shell has actually been served, which means the session already exists.
 */
window.location.replace(FLEET_SURFACE_URL);
