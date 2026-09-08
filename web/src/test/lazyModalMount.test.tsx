import { useEffect, useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ModalShell } from "../features/soc/components";
import { PANELS } from "../features/soc/dashboard";

/**
 * WHAT THIS PINS: a closed modal must not run its body.
 *
 * ModalShell used to render `children` unconditionally and hide the surface
 * with a missing `is-open` class, so every body the console offers — its
 * polls, its effects, its subscriptions — was mounted and running on every
 * dashboard load, behind doors the operator never opened. That is what blocks
 * folding the fleet console in: mounted permanently it would put a 5s
 * tenant-wide fan-out behind a closed door for every analyst.
 *
 * The two halves of the contract are equally load-bearing:
 *
 *  - The BODY is lazy. Nothing under `children` exists until the surface is
 *    first opened.
 *  - The CLOSED SHELL is unchanged. The e2e suite selects `[data-panel]` on
 *    surfaces that are still shut and asserts `toHaveClass(/is-open/)` rather
 *    than `toBeVisible()`, precisely because the shell is in the DOM before it
 *    is visible. Its element, its data-panel, its aria-hidden, its class list
 *    and its head (eyebrow, title, close button, description) must read
 *    exactly as they did before.
 *
 * And the decision that had to be made either way: once opened, the body is
 * KEPT. Re-opening a surface must not throw away a half-typed reason or a
 * scrolled list, and must not pay a fresh fan-out of fetches. That is asserted
 * here, not left to a comment, so a later "unmount on close" is a deliberate
 * change to a failing test rather than a quiet regression in in-progress work.
 */

const PANEL = PANELS["watchlist-modal"];

function Body({ onMount }: { onMount: () => void }) {
  const [note, setNote] = useState("");
  useEffect(() => {
    // Stands in for the poll/subscription a real body starts on mount.
    onMount();
  }, [onMount]);
  return (
    <div className="soc-body-probe">
      <label htmlFor="probe-note">Audit reason</label>
      <input id="probe-note" value={note} onChange={(event) => setNote(event.target.value)} />
    </div>
  );
}

function Shell({ open, onMount }: { open: boolean; onMount: () => void }) {
  return (
    <ModalShell panel={PANEL} open={open} onClose={() => {}}>
      <Body onMount={onMount} />
    </ModalShell>
  );
}

function backdrop(): HTMLElement {
  const el = document.querySelector(`[data-panel="${PANEL.id}"]`);
  if (!el) throw new Error("the shell itself did not render");
  return el as HTMLElement;
}

describe("ModalShell mounts its body lazily", () => {
  it("renders the closed shell exactly as before, and none of its body", () => {
    const onMount = vi.fn();
    render(<Shell open={false} onMount={onMount} />);

    const back = backdrop();
    expect(back.tagName).toBe("DIV");
    expect(back.getAttribute("data-panel")).toBe(PANEL.id);
    expect(back.getAttribute("aria-hidden")).toBe("true");
    // The whole class list, not a substring: a closed surface carries no
    // `is-open`, and specs read this attribute directly.
    expect(back.className).toBe("soc-modal-back");

    // The head is part of the closed markup and stays: it holds no effects,
    // and it is what the shell is recognised by while shut.
    const card = back.querySelector(".soc-modal-card") as HTMLElement;
    expect(card.className).toBe("soc-modal-card");
    expect(card.getAttribute("role")).toBe("dialog");
    expect(card.getAttribute("aria-modal")).toBe("true");
    expect(card.getAttribute("aria-label")).toBe(PANEL.title);
    expect(card.querySelector(".soc-modal-head .soc-eyebrow")?.textContent).toBe(PANEL.mode);
    expect(card.querySelector(".soc-modal-head h2")?.textContent).toBe(PANEL.title);
    expect(card.querySelector(".soc-close-button")).not.toBeNull();
    expect(card.querySelector(".soc-panel-copy")?.textContent).toBe(PANEL.description);

    // The body, and only the body, is absent.
    expect(card.querySelector(".soc-body-probe")).toBeNull();
    expect(screen.queryByLabelText("Audit reason")).toBeNull();
    expect(onMount, "a closed surface started its body's work anyway").not.toHaveBeenCalled();

    // Nothing beneath the header — the shape the probe suite reads as "the
    // shell opened with nothing beneath its header" for an OPEN surface.
    expect(card.querySelectorAll(":scope > *:not(.soc-modal-head):not(.soc-panel-copy)")).toHaveLength(0);
  });

  it("mounts the body when the surface opens", () => {
    const onMount = vi.fn();
    const view = render(<Shell open={false} onMount={onMount} />);
    view.rerender(<Shell open onMount={onMount} />);

    const back = backdrop();
    expect(back.className).toBe("soc-modal-back is-open");
    expect(back.getAttribute("aria-hidden")).toBe("false");
    expect(screen.getByLabelText("Audit reason")).toBeTruthy();
    expect(onMount).toHaveBeenCalledTimes(1);

    // The body is a DIRECT child of the card, alongside the head and the copy
    // — no wrapper was introduced by the gating.
    const card = back.querySelector(".soc-modal-card") as HTMLElement;
    const bodyNodes = card.querySelectorAll(":scope > *:not(.soc-modal-head):not(.soc-panel-copy)");
    expect(bodyNodes).toHaveLength(1);
    expect(bodyNodes[0].className).toBe("soc-body-probe");
  });

  it("keeps the body mounted after close, with its in-progress state intact", async () => {
    const user = userEvent.setup();
    const onMount = vi.fn();
    const view = render(<Shell open={false} onMount={onMount} />);

    view.rerender(<Shell open onMount={onMount} />);
    await user.type(screen.getByLabelText("Audit reason"), "half-typed");

    view.rerender(<Shell open={false} onMount={onMount} />);

    // The closed shell reads exactly as it did before it was ever opened.
    const back = backdrop();
    expect(back.className).toBe("soc-modal-back");
    expect(back.getAttribute("aria-hidden")).toBe("true");

    // But the body survives the close: re-opening is cheap and the operator's
    // half-typed reason is still there.
    const note = screen.getByLabelText("Audit reason") as HTMLInputElement;
    expect(note.value, "closing the surface threw the operator's work away").toBe("half-typed");
    expect(onMount, "the body was re-mounted, so its poll restarted").toHaveBeenCalledTimes(1);

    view.rerender(<Shell open onMount={onMount} />);
    expect((screen.getByLabelText("Audit reason") as HTMLInputElement).value).toBe("half-typed");
    expect(onMount).toHaveBeenCalledTimes(1);
  });

  it("mounts nothing while the surface is only ever closed, however often it re-renders", () => {
    const onMount = vi.fn();
    const view = render(<Shell open={false} onMount={onMount} />);
    for (let i = 0; i < 5; i += 1) view.rerender(<Shell open={false} onMount={onMount} />);
    expect(screen.queryByLabelText("Audit reason")).toBeNull();
    expect(onMount).not.toHaveBeenCalled();
  });

  it("gates a full-screen surface the same way, and keeps its closed class list", () => {
    const onMount = vi.fn();
    const view = render(
      <ModalShell panel={PANEL} open={false} onClose={() => {}} wide fullScreen>
        <Body onMount={onMount} />
      </ModalShell>
    );
    const back = backdrop();
    expect(back.className).toBe("soc-modal-back is-fullscreen");
    expect((back.querySelector(".soc-modal-card") as HTMLElement).className).toBe(
      "soc-modal-card is-wide is-fullscreen"
    );
    expect(screen.queryByLabelText("Audit reason")).toBeNull();
    expect(onMount).not.toHaveBeenCalled();

    view.rerender(
      <ModalShell panel={PANEL} open onClose={() => {}} wide fullScreen>
        <Body onMount={onMount} />
      </ModalShell>
    );
    expect(back.className).toBe("soc-modal-back is-open is-fullscreen");
    expect(screen.getByLabelText("Audit reason")).toBeTruthy();
    expect(onMount).toHaveBeenCalledTimes(1);
  });
});
