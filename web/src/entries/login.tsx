import { renderApp } from "../app/render";
import { LoginPage } from "../features/login/LoginPage";
import { initTheme } from "../lib/theme";

// Apply the OS theme before React mounts so the first paint is already correct
// (no flash of dark on a light desktop).
initTheme();

renderApp(<LoginPage />, "the login page");
