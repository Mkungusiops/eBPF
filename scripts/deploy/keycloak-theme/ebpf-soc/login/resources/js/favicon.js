/* Theme-aware favicon for the Keycloak login pages.
 *
 * Two problems this solves, neither of which the theme's CSS can touch:
 *
 * 1. Keycloak's stock template hardcodes `<link rel="icon" href=".../favicon.ico">`.
 *    A .ico is a raster: it cannot carry a prefers-color-scheme media query, so
 *    the login pages were stuck with one artwork while the console's own pages
 *    swap theirs.
 *
 * 2. Chromium keeps a DEDICATED favicon store, separate from the HTTP cache,
 *    keyed on the icon URL. Replacing the file on disk changes nothing for
 *    anyone who has already visited, because Keycloak's resourcesPath is
 *    versioned by the SERVER BUILD, not by theme content — so the URL never
 *    changes and the browser never looks again. Cache-Control: no-cache does
 *    not help; the favicon store ignores it.
 *
 * Pointing the link at the SVG with a version query fixes both: a new URL the
 * favicon store has never seen, and an asset that can follow the OS theme.
 * Bump V when the artwork changes.
 */
(function () {
  var V = "2";
  function resourcesPath() {
    // Derive it from the tag Keycloak already rendered rather than hardcoding
    // the version segment, which changes with the Keycloak release.
    var link = document.querySelector('link[rel="icon"]');
    var href = link && link.getAttribute("href");
    if (!href) return null;
    return href.replace(/\/img\/favicon\.[a-z]+$/, "");
  }
  var base = resourcesPath();
  if (!base) return;

  var link = document.querySelector('link[rel="icon"]');
  function apply(light) {
    link.setAttribute("type", "image/svg+xml");
    link.setAttribute("href", base + "/img/favicon" + (light ? "-light" : "") + ".svg?v=" + V);
  }
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;
  apply(mq ? mq.matches : false);
  if (mq && mq.addEventListener) mq.addEventListener("change", function (e) { apply(e.matches); });
})();
