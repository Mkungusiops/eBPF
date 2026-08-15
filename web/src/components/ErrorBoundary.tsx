import React from "react";

/**
 * ErrorBoundary — keeps one bad render from blanking the console.
 *
 * There was no error boundary anywhere in this app. `renderApp` mounted the
 * tree inside `StrictMode` alone, so a single throw in any of SocRoute's ~5,900
 * lines — an unguarded `map.get(...)!`, a field missing from an API payload —
 * unmounted the entire SOC console to a white page, with no message and no way
 * back except a manual reload. That is a poor failure mode for any app and an
 * unacceptable one for the screen an operator is looking at during an incident.
 *
 * The fallback deliberately states what still works: the engine keeps enforcing
 * autonomously whether or not this console is rendering, and an operator seeing
 * a blank screen mid-incident needs to know that before anything else.
 */
type Props = {
  children: React.ReactNode;
  /** Shown in the fallback so the operator knows which surface failed. */
  surface?: string;
};

type State = { error: Error | null };

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // Console only: there is no client-side error sink to ship this to, and
    // inventing one silently would be worse than leaving it visible in devtools.
    console.error("[console] render error", error, info.componentStack);
  }

  private reload = () => window.location.reload();

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;

    const surface = this.props.surface ? ` in ${this.props.surface}` : "";
    return (
      <div role="alert" className="console-error-boundary">
        <h1>This view stopped rendering</h1>
        <p>
          Something went wrong{surface}. <strong>Enforcement is unaffected</strong> — agents
          apply policy on the host and keep doing so whether or not this console is up.
        </p>
        <p>Reloading usually clears it. If it returns, the message below identifies the fault.</p>
        <pre>{error.message || String(error)}</pre>
        <button type="button" onClick={this.reload}>
          Reload console
        </button>
      </div>
    );
  }
}
