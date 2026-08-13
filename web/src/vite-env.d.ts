/// <reference types="vite/client" />

// Each route imports its own stylesheet as a side effect (`import "./x.css"`).
// Without an ambient module declaration, TypeScript/the IDE reports
// "Cannot find module or type declarations for side-effect import" on those
// lines. Vite handles the actual bundling; this just gives TS the types.
declare module "*.css";
