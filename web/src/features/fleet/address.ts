/**
 * THE ADDRESS AN OPERATOR ARRIVES ON — not a mirror of what is open.
 *
 * The fleet view is a surface inside the SOC console, but it kept an address:
 * /fleet is bookmarked, the live probe suite signs in at it, and the command
 * palette offers it as a route. /fleet is now a redirect (src/entries/fleet.tsx)
 * and this is what it redirects to.
 *
 * IT IS WRITTEN IN ONE PLACE AND READ IN ONE PLACE, AND NEITHER IS THE SURFACE.
 * The redirect entry sets it; SocModals reads it ONCE, at mount, and opens the
 * surface it names (useAddressedSurface). Nothing else writes it, and nothing
 * clears it.
 *
 * Which door an operator came through therefore decides whether the address
 * names what they are looking at. The PALETTE ends up with the fragment set —
 * its entry is a route command that assigns /fleet, and the redirect then
 * replaces the location with this address — as do a bookmark and a
 * middle-clicked rail link, all three arriving the same way. A plain left click
 * on the RAIL does not: it preventDefaults and opens the surface in place, so
 * the address stays bare and that view cannot be shared by copying the URL.
 * And because nothing clears it, /#fleet still reads /#fleet after the operator
 * has closed the surface — a reload opens it again. Making the fragment track the open surface would
 * mean writing it on every open and close from the console that owns the
 * surfaces; that is a change nobody has made, and this constant does not
 * pretend otherwise.
 *
 * A FRAGMENT, NOT A QUERY PARAMETER, and the choice is not cosmetic:
 *
 *  • A fragment is the part of a URL that has always meant "which part of this
 *    document" — which is exactly what an overlay surface is. A query parameter
 *    would claim the server has something to say about it; it does not, and
 *    both servers would serve the same shell either way.
 *  • It never leaves the browser. This console already puts one query parameter
 *    on the wire — `?tenant=`, which lib/api.ts stamps on every scoped request
 *    and both servers authorize against — so a second, cosmetic one on the page
 *    URL would sit one character away from the only parameter that decides
 *    whose hosts a containment reaches. Keeping the surface address in the
 *    fragment means it can never be mistaken for scope, never reaches an access
 *    log, and cannot be replayed as a request.
 *  • It survives the sign-in bounce. An unauthenticated /fleet is a 303 to
 *    /login and back, and the fragment is only attached afterwards, by the
 *    redirect the /fleet entry performs once the shell has actually loaded.
 *
 * One constant, imported by the redirect entry and by the reader in SocModals,
 * so the two cannot disagree about the spelling.
 */
export const FLEET_SURFACE_HASH = "#fleet";

/** The full address the /fleet entry redirects to: the SOC console, fleet open. */
export const FLEET_SURFACE_URL = `/${FLEET_SURFACE_HASH}`;
