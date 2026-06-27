import { useVirtualizer } from "@tanstack/react-virtual";
import { ReactNode, RefObject, useCallback, useRef } from "react";

export function VirtualList<T>({
  items,
  estimateSize,
  renderItem,
  className,
  getKey,
  empty,
  viewportRef,
  overscan = 8
}: {
  items: T[];
  estimateSize: number;
  renderItem: (item: T, index: number) => ReactNode;
  className?: string;
  getKey?: (item: T, index: number) => string | number;
  empty?: ReactNode;
  viewportRef?: RefObject<HTMLDivElement>;
  overscan?: number;
}) {
  const parentRef = useRef<HTMLDivElement | null>(null);
  const setViewportRef = useCallback(
    (node: HTMLDivElement | null) => {
      parentRef.current = node;
      if (viewportRef) {
        (viewportRef as { current: HTMLDivElement | null }).current = node;
      }
    },
    [viewportRef]
  );

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => estimateSize,
    getItemKey: getKey ? (index) => getKey(items[index], index) : undefined,
    overscan
  });

  if (items.length === 0) {
    return <div ref={setViewportRef} className={className}>{empty}</div>;
  }

  return (
    <div ref={setViewportRef} className={className}>
      <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
        {virtualizer.getVirtualItems().map((virtualRow) => (
          <div
            key={virtualRow.key}
            data-index={virtualRow.index}
            ref={virtualizer.measureElement}
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: "100%",
              transform: `translateY(${virtualRow.start}px)`
            }}
          >
            {renderItem(items[virtualRow.index], virtualRow.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
