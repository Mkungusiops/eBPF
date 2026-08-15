/**
 * Every fleet panel is headed the same way. Shared so the rail, the host table,
 * the cgroup bars and the feeds cannot drift into three different headings.
 */
export function PanelTitle({ title }: { title: string }) {
  return <h2 className="fleet-panel__title">{title}</h2>;
}
