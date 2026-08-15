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
 *  3. Selection and expansion are reconciled against the macs the engine just
 *     returned. A device that ages out of the table must not stay silently
 *     selected — the next bulk Choke would act on a device the operator can no
 *     longer see.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";

import { isAbortError, isDisabledError, type DevicesApi } from "./api";
import type { DeviceDataPlaneState, DeviceEntry, DeviceFlow } from "./types";
import { DISABLED_MESSAGE, sortFlows } from "./utils";

export interface FlowLoadState {
  loading: boolean;
  error?: string;
  flows?: DeviceFlow[];
}

export interface DeviceInventory {
  state: DeviceDataPlaneState | null;
  devices: DeviceEntry[];
  loading: boolean;
  refreshing: boolean;
  disabledMessage: string | null;
  error: string | null;
  lastUpdatedAt: number | null;
  selected: Set<string>;
  expanded: Set<string>;
  flows: Record<string, FlowLoadState>;
  setDisabledMessage: Dispatch<SetStateAction<string | null>>;
  /** Background re-read: keeps the table on screen, no loading skeleton. */
  refresh: () => void;
  toggleSelected: (mac: string, checked: boolean) => void;
  setAllSelected: (checked: boolean) => void;
  clearSelection: () => void;
  toggleFlows: (mac: string) => void;
}

export function useDeviceInventory(api: DevicesApi, pollMs: number): DeviceInventory {
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
  const expandedRef = useRef(expanded);

  useEffect(() => {
    expandedRef.current = expanded;
  }, [expanded]);

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

  useEffect(() => {
    const controller = new AbortController();
    void loadDevices({ signal: controller.signal });
    const interval = window.setInterval(() => {
      void loadDevices({ quiet: true, signal: controller.signal });
    }, pollMs);
    return () => {
      controller.abort();
      window.clearInterval(interval);
    };
  }, [loadDevices, pollMs]);

  const refresh = useCallback(() => {
    void loadDevices({ quiet: true });
  }, [loadDevices]);

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
    toggleSelected,
    setAllSelected,
    clearSelection,
    toggleFlows
  };
}
