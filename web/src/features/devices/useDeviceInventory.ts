/**
 * The device console's read path: plane state, the device table, per-device
 * flows, and the selection/expansion that hang off them.
 *
 * Three things here are load-bearing and must not be loosened:
 *
 *  1. One `AbortController` covers the first load AND every poll tick, and the
 *     cleanup aborts it alongside `clearInterval`. Without that, a poll already
 *     in flight when the route unmounts still resolves and writes state.
 *  2. `isAbortError` is checked at every catch site. An aborted fetch rejects
 *     like any other failure, so an unchecked catch renders a teardown as
 *     "Device state could not be refreshed" in the operator's face.
 *  3. The whoami read RETRIES, and every attempt is on a DEADLINE. It is the
 *     gate on every containment control on this route, and it disarmed the
 *     kill-switch for a whole session twice over: first when it ran once per
 *     mount and swallowed its rejection, then when a read that never settled
 *     held the in-flight guard open so no retry, poll or Refresh could ask
 *     again.
 *  4. Selection and expansion are reconciled against the macs the engine just
 *     returned. A device that ages out of the table must not stay silently
 *     selected — the next bulk Choke would act on a device the operator can no
 *     longer see.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

import { isAbortError, isDisabledError, type DevicesApi } from "./api";
import type { DeviceDataPlaneState, DeviceEntry, DeviceFlow } from "./types";
import { DISABLED_MESSAGE, sortFlows } from "./utils";

/**
 * `pending`    — asked, no answer yet (or not asked yet). Withholds.
 * `answered`   — the server replied; `canRespond` carries what it said.
 * `unanswered` — the request failed, or ran past its deadline without ever
 *                settling. Still withholds, but a retry is scheduled, so this
 *                is transient rather than terminal.
 */
export type DeviceWhoamiStatus = "pending" | "answered" | "unanswered";

/**
 * Retry cadence for a whoami that did not come back. Bounded backoff rather
 * than a tight loop: a control plane that is down should not be hammered by
 * every open device console, but the console must still recover on its own the
 * moment it comes back — an operator should not have to reload the page to get
 * the kill-switch returned to them.
 */
const WHOAMI_RETRY_BASE_MS = 750;
const WHOAMI_RETRY_MAX_MS = 15_000;

/**
 * How long the permission question may stay open before the console treats
 * silence as an answer of its own.
 *
 * A rejected whoami was already handled: it sets `unanswered` and arms the
 * backoff. A whoami that simply NEVER SETTLES was not, and it is the more
 * common failure — a half-open TCP connection through a load balancer, which
 * is the shape of the control-plane outages this estate has actually seen. The
 * in-flight guard below is what makes it fatal: a request that never settles
 * never clears the flag, so the backoff timer, the poll tick and the operator's
 * Refresh all bail out on it forever, the status stays `pending`, and every
 * containment control on the route stays disabled for the whole session. That
 * is the exact wedge the retry was written to remove, reached through the front
 * door instead. The deadline turns the unanswered question into an answered
 * "could not be reached", which is a state the retry path can act on.
 */
const WHOAMI_TIMEOUT_MS = 8_000;

/**
 * The retry base is a PARAMETER rather than a constant so a test can prove
 * which mechanism recovered the console. Refresh and the backoff timer both end
 * in another whoami, so a test that races a 750ms timer proves nothing when the
 * machine is loaded — it passes for the wrong reason, or flakes. Given a base
 * far longer than the assertion's own deadline, the timer provably cannot have
 * fired, so a second attempt can only have come from Refresh.
 */
export interface DeviceInventoryOptions {
  whoamiRetryBaseMs?: number;
  /**
   * Deadline for a single whoami, injectable for the same reason as the retry
   * base: a test must be able to drive a hung read to its timeout without
   * waiting eight real seconds, and without fake timers, which deadlock the
   * act() flush this hook's async reads run through.
   */
  whoamiTimeoutMs?: number;
}

export interface FlowLoadState {
  loading: boolean;
  error?: string;
  flows?: DeviceFlow[];
}

export interface DeviceInventory {
  state: DeviceDataPlaneState | null;
  devices: DeviceEntry[];
  /**
   * whoami's `can_respond`: may this account send device containment writes?
   *
   * `null` means the server ANSWERED and did not publish the field, which is
   * PERMITTED — only the multi-tenant control plane publishes it. It is NOT
   * "nobody has answered yet"; that is `whoamiStatus`, and the two must stay
   * apart, because arming containment on an unanswered question is the bug the
   * shared authority store exists to prevent.
   */
  canRespond: boolean | null;
  /**
   * Whether the permission question has been ANSWERED, is still open, or was
   * asked and could not be reached.
   *
   * `unanswered` is a retrying state, not a terminal one — see the whoami
   * loader below. The route needs it to say "still asking" rather than "your
   * account is read-only", which would be a lie about a responder.
   */
  whoamiStatus: DeviceWhoamiStatus;
  loading: boolean;
  refreshing: boolean;
  disabledMessage: string | null;
  error: string | null;
  lastUpdatedAt: number | null;
  selected: Set<string>;
  expanded: Set<string>;
  flows: Record<string, FlowLoadState>;
  setDisabledMessage: Dispatch<SetStateAction<string | null>>;
  /**
   * Background re-read: keeps the table on screen, no loading skeleton. Re-asks
   * whoami too — the Refresh control is the operator's only manual way out of a
   * console whose permission read failed, and refreshing the table while
   * leaving containment disarmed forever is what made a single failed
   * /api/whoami a session-long outage of every containment control.
   */
  refresh: () => void;
  /** Re-ask the permission question on its own, without re-reading the table. */
  refreshWhoami: () => void;
  toggleSelected: (mac: string, checked: boolean) => void;
  setAllSelected: (checked: boolean) => void;
  clearSelection: () => void;
  toggleFlows: (mac: string) => void;
}

export function useDeviceInventory(
  api: DevicesApi,
  pollMs: number,
  options: DeviceInventoryOptions = {}
): DeviceInventory {
  const retryBaseMs = options.whoamiRetryBaseMs ?? WHOAMI_RETRY_BASE_MS;
  const whoamiTimeoutMs = options.whoamiTimeoutMs ?? WHOAMI_TIMEOUT_MS;
  const [state, setState] = useState<DeviceDataPlaneState | null>(null);
  const [devices, setDevices] = useState<DeviceEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [disabledMessage, setDisabledMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(null);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [flows, setFlows] = useState<Record<string, FlowLoadState>>({});
  const [canRespond, setCanRespond] = useState<boolean | null>(null);
  const [whoamiStatus, setWhoamiStatus] = useState<DeviceWhoamiStatus>(() =>
    api.fetchWhoami ? "pending" : "answered"
  );
  const whoamiInFlight = useRef(false);
  const whoamiAttempts = useRef(0);
  const whoamiRetryTimer = useRef<number | null>(null);
  const loadWhoamiRef = useRef<(signal?: AbortSignal) => void>(() => {});
  const expandedRef = useRef(expanded);
  // Read inside the poll tick, which must not re-subscribe every time the
  // status changes — a status-dependent interval would restart the poll clock.
  const whoamiStatusRef = useRef(whoamiStatus);

  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);

  useEffect(() => {
    whoamiStatusRef.current = whoamiStatus;
  }, [whoamiStatus]);

  const refreshFlows = useCallback(
    async (mac: string, signal?: AbortSignal) => {
      // Only show the loading state on first fetch; background re-polls update
      // silently (keep showing existing flows) so expanded rows don't flash.
      setFlows((previous) => ({
        ...previous,
        [mac]: { ...previous[mac], loading: !previous[mac]?.flows, error: undefined }
      }));
      try {
        const response = await api.fetchFlows(mac, { signal });
        setFlows((previous) => ({
          ...previous,
          [mac]: { loading: false, flows: sortFlows(response.flows ?? []) }
        }));
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (isDisabledError(caught)) {
          setDisabledMessage(DISABLED_MESSAGE);
          return;
        }
        setFlows((previous) => ({
          ...previous,
          [mac]: {
            loading: false,
            error: caught instanceof Error ? caught.message : "connections unavailable"
          }
        }));
      }
    },
    [api]
  );

  const loadDevices = useCallback(
    async (options: { quiet?: boolean; signal?: AbortSignal } = {}) => {
      if (options.quiet) setRefreshing(true);
      else setLoading(true);
      setError(null);
      try {
        const nextState = await api.fetchState({ signal: options.signal });
        const nextDevices = await api.fetchDevices({ signal: options.signal });
        if (options.signal?.aborted) return;
        const knownMacs = new Set(nextDevices.map((device) => device.mac));
        setState(nextState);
        setDevices(nextDevices);
        setDisabledMessage(null);
        setLastUpdatedAt(Date.now());
        setSelected((previous) => new Set([...previous].filter((mac) => knownMacs.has(mac))));
        for (const mac of expandedRef.current) {
          if (knownMacs.has(mac)) void refreshFlows(mac, options.signal);
        }
      } catch (caught) {
        if (isAbortError(caught)) return;
        if (isDisabledError(caught)) {
          setDisabledMessage(DISABLED_MESSAGE);
          setState(null);
          setDevices([]);
          setSelected(new Set());
          return;
        }
        setError(caught instanceof Error ? caught.message : "Unable to load device state");
      } finally {
        if (!options.signal?.aborted) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [api, refreshFlows]
  );

  /**
   * Ask the server what this account may do — and keep asking until it says.
   *
   * A whoami that fails leaves `canRespond` at null and the status at
   * `unanswered`; neither is an answer, and the shared authority store
   * (features/soc/api.ts) records nothing, so containment stays withheld. That
   * half is deliberate: a console that has never been told may not arm a
   * kill-switch on a guess.
   *
   * A read that never settles is treated as a failure once its deadline passes
   * — see WHOAMI_TIMEOUT_MS. "Still asking" is only honest for a bounded while;
   * past that the console owes the operator the third sentence, "asked and
   * could not be reached", and a retry it can actually run.
   *
   * But the other half is just as real, and is the failure this loader exists
   * to prevent: the read used to run ONCE per mount and swallow the rejection,
   * so a single dropped /api/whoami left the store at "loading" for the whole
   * session and every device containment control — kill-switch, mode toggle,
   * bulk Choke/Thaw, every row rung — stayed disabled until the operator
   * reloaded the page. So the question is re-asked: on a bounded backoff after
   * a failure, on the inventory poll tick while it is still unanswered, and on
   * the operator's Refresh. "Loading" is therefore transient — the moment the
   * server answers, the answer reaches the store and the controls settle into
   * whatever it said, with no remount.
   */
  const loadWhoami = useCallback(
    async (signal?: AbortSignal) => {
      const fetchWhoami = api.fetchWhoami;
      if (!fetchWhoami) {
        // No permission model to consult at all is an answered question, not an
        // open one — see DevicesRoute, which records the same for the store.
        setWhoamiStatus("answered");
        return;
      }
      // One question at a time: the poll tick, the backoff timer and Refresh
      // can all land together, and three concurrent reads would only make the
      // control plane that is already struggling struggle harder.
      if (whoamiInFlight.current) return;
      whoamiInFlight.current = true;
      // ...but ONE QUESTION AT A TIME ONLY WORKS IF EVERY QUESTION ENDS. The
      // guard above is only safe because this read is on a deadline: silence
      // becomes an "unreachable" answer within a bounded time, the flag is
      // released, and the backoff/poll/Refresh paths can ask again. Without it
      // a hung request holds the flag for the life of the session.
      //
      // The deadline abandons the request rather than aborting it: the signal
      // here is the route's single mount controller, shared with the inventory
      // poll, so aborting it to time out a whoami would stop the device table
      // too. An abandoned read is harmless — nothing awaits its result any
      // more, so a late resolution cannot write stale authority over a newer
      // answer.
      let deadlineTimer: number | null = null;
      const request = fetchWhoami({ signal });
      // Once the race is lost, nothing is left awaiting this promise, and a
      // late rejection with no handler is an unhandled rejection. Claim it.
      request.catch(() => {});
      try {
        const identity = await Promise.race([
          request,
          new Promise<never>((_, reject) => {
            deadlineTimer = window.setTimeout(
              () => reject(new Error("whoami timed out")),
              whoamiTimeoutMs
            );
          })
        ]);
        if (signal?.aborted) return;
        whoamiAttempts.current = 0;
        setCanRespond(identity.canRespond ?? null);
        setWhoamiStatus("answered");
      } catch (caught) {
        if (isAbortError(caught) || signal?.aborted) return;
        setWhoamiStatus("unanswered");
        const attempt = (whoamiAttempts.current += 1);
        const delay = Math.min(retryBaseMs * 2 ** (attempt - 1), WHOAMI_RETRY_MAX_MS);
        if (whoamiRetryTimer.current !== null) window.clearTimeout(whoamiRetryTimer.current);
        whoamiRetryTimer.current = window.setTimeout(() => {
          whoamiRetryTimer.current = null;
          loadWhoamiRef.current(signal);
        }, delay);
      } finally {
        if (deadlineTimer !== null) window.clearTimeout(deadlineTimer);
        whoamiInFlight.current = false;
      }
    },
    [api, retryBaseMs, whoamiTimeoutMs]
  );

  // The backoff timer fires long after the render that scheduled it, so it goes
  // through a ref rather than closing over one render's callback.
  useEffect(() => {
    loadWhoamiRef.current = (signal) => {
      void loadWhoami(signal);
    };
  }, [loadWhoami]);

  useEffect(() => {
    const controller = new AbortController();
    void loadDevices({ signal: controller.signal });
    void loadWhoami(controller.signal);
    const interval = window.setInterval(() => {
      void loadDevices({ quiet: true, signal: controller.signal });
      // Re-asked alongside the table only while the answer is still missing: a
      // grant that has been read does not change inside a session, so polling
      // it every four seconds would be traffic for nothing — but an unanswered
      // one must never be left to sit.
      if (whoamiStatusRef.current !== "answered") void loadWhoami(controller.signal);
    }, pollMs);
    return () => {
      controller.abort();
      window.clearInterval(interval);
      if (whoamiRetryTimer.current !== null) {
        window.clearTimeout(whoamiRetryTimer.current);
        whoamiRetryTimer.current = null;
      }
    };
  }, [loadDevices, loadWhoami, pollMs]);

  const refresh = useCallback(() => {
    void loadDevices({ quiet: true });
    // The Refresh control re-asks the permission question too. It is the only
    // manual recovery an operator has when the whoami read failed, and a
    // Refresh that reloads the table while leaving containment disarmed is the
    // shape of the bug this fixes.
    void loadWhoami();
  }, [loadDevices, loadWhoami]);

  const refreshWhoami = useCallback(() => {
    void loadWhoami();
  }, [loadWhoami]);

  const toggleSelected = useCallback((mac: string, checked: boolean) => {
    setSelected((previous) => {
      const next = new Set(previous);
      if (checked) next.add(mac);
      else next.delete(mac);
      return next;
    });
  }, []);

  const setAllSelected = useCallback(
    (checked: boolean) => {
      setSelected(checked ? new Set(devices.map((device) => device.mac)) : new Set());
    },
    [devices]
  );

  const clearSelection = useCallback(() => {
    setSelected(new Set());
  }, []);

  const toggleFlows = useCallback(
    (mac: string) => {
      let shouldOpen = false;
      setExpanded((previous) => {
        const next = new Set(previous);
        if (next.has(mac)) {
          next.delete(mac);
        } else {
          next.add(mac);
          shouldOpen = true;
        }
        return next;
      });
      if (shouldOpen) void refreshFlows(mac);
    },
    [refreshFlows]
  );

  return {
    state,
    devices,
    canRespond,
    whoamiStatus,
    loading,
    refreshing,
    disabledMessage,
    error,
    lastUpdatedAt,
    selected,
    expanded,
    flows,
    setDisabledMessage,
    refresh,
    refreshWhoami,
    toggleSelected,
    setAllSelected,
    clearSelection,
    toggleFlows
  };
}
