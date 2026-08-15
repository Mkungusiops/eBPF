// The four context panels beside the triage queue: what techniques were seen,
// which processes are scoring, which indicators appeared, and who was talked to.
//
// Two of them are bound by the alert buffer and two by the event buffer, which
// is why each carries its own coverage pill rather than the page carrying one
// banner for all four.
import { PanelFrame } from "./components";
import { PANELS } from "./dashboard";
import { CoveragePill, IocList, MiniBarList, NetworkList } from "./rows";
import type { SocWindowModel } from "./useSocWindowModel";

export function RightRail({
  model,
  onOpenProcess
}: {
  model: SocWindowModel;
  onOpenProcess: (execId: string) => void;
}) {
  const { mitreRows, techniqueMapped, topProcesses, iocs, networkRows, windowCoverage } = model;
  return (
    <div className="soc-right-rail">
      <PanelFrame panel={PANELS["mitre-coverage"]}>
        <MiniBarList
          rows={mitreRows}
          empty={
            techniqueMapped
              ? "No MITRE techniques observed in this range."
              : "This server publishes no policy→ATT&CK mapping, so coverage cannot be computed here."
          }
        />
      </PanelFrame>
      <PanelFrame panel={PANELS["top-processes"]} status={<CoveragePill feed={windowCoverage.alerts} />}>
        <MiniBarList
          rows={topProcesses.map((row) => ({
            label: row.process,
            value: row.score,
            meta: `${row.pid ? `pid ${row.pid} · ` : ""}${row.count} alert${row.count === 1 ? "" : "s"}`,
            id: row.execId
          }))}
          empty="No scored processes yet."
          onClick={onOpenProcess}
        />
      </PanelFrame>
      <PanelFrame panel={PANELS["iocs-observed"]} status={<CoveragePill feed={windowCoverage.events} />}>
        <IocList files={iocs.files} peers={iocs.peers} />
      </PanelFrame>
      <PanelFrame panel={PANELS["network-connections"]} status={<CoveragePill feed={windowCoverage.events} />}>
        <NetworkList rows={networkRows} />
      </PanelFrame>
    </div>
  );
}
