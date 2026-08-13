import type { Config } from "tailwindcss";

export default {
  content: ["./*.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["class", ".theme-dark"],
  theme: {
    extend: {
      colors: {
        surface: "rgb(var(--surface) / <alpha-value>)",
        panel: "rgb(var(--panel) / <alpha-value>)",
        row: "rgb(var(--row) / <alpha-value>)",
        text: "rgb(var(--text) / <alpha-value>)",
        muted: "rgb(var(--muted) / <alpha-value>)",
        dim: "rgb(var(--dim) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        good: "rgb(var(--good) / <alpha-value>)",
        warn: "rgb(var(--warn) / <alpha-value>)",
        danger: "rgb(var(--danger) / <alpha-value>)",
        info: "rgb(var(--info) / <alpha-value>)"
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "SFMono-Regular", "ui-monospace", "monospace"]
      },
      boxShadow: {
        glow: "0 0 0 1px rgb(var(--accent) / 0.16), 0 20px 70px rgb(0 0 0 / 0.32)"
      }
    }
  },
  safelist: [
    "state-pristine",
    "state-throttled",
    "state-tarpit",
    "state-quarantined",
    "state-severed",
    "severity-critical",
    "severity-high",
    "severity-medium",
    "severity-low",
    "severity-info"
  ],
  plugins: []
} satisfies Config;
