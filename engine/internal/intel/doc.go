// Package intel matches observed indicators — IPs, domains and file hashes —
// against threat-intelligence feeds, at detection time on a sensor and at
// ingest on the control plane.
//
// # The design decision that shapes everything else
//
// MATCHING IS LOCAL. Feeds are pulled INTO the deployment and evaluated in
// process; an observable is never sent out to ask whether it is bad.
//
// That is not an efficiency choice, it is the product requirement. A
// query-time reputation API turns every outbound connection this platform
// observes into a disclosure to a third party of who the customer talks to —
// a SOC tool that leaks its customer's traffic graph to a vendor is a breach
// with a support contract. It would also make detection depend on someone
// else's uptime and rate limit, in the enforcement path, which the autonomy
// contract (architecture.md §6) forbids.
//
// So: feeds are files. An operator drops them in, or an optional refresher
// fetches them on a schedule and writes them to disk. Both paths converge on
// the same on-disk set, and a failed refresh leaves the last good copy in
// place rather than degrading to an empty set — silently matching nothing is
// the worst possible failure for this component, because it is indistinguishable
// from a clean estate.
//
// # What it will not match
//
// False positives here are expensive: an indicator hit scores high enough to
// drive containment, so a bad match can sever a production host. Three
// exclusions are structural rather than configurable:
//
//   - Private, loopback, link-local, CGNAT and multicast addresses. Public
//     feeds contain RFC1918 space surprisingly often, and an estate whose every
//     internal flow matches a C2 list is an estate that turns the feature off.
//   - Anything on the operator's allowlist, which is checked BEFORE the feeds.
//   - Domains matched only by suffix at a public-suffix-like depth: a feed
//     entry of "com" or "co.uk" is discarded at load rather than matching
//     everything.
//
// # Scoring
//
// A confirmed indicator is the strongest single signal available to this
// platform — far stronger than any behavioural rule, because it is external
// corroboration rather than inference. Points scale with the feed's stated
// confidence, and the highest tier is enough to carry a chain to the critical
// band on its own. That is deliberate: if a process talks to a known C2
// address, the analyst should not have to wait for it to also read /etc/shadow.
package intel
