import { renderApp } from "../app/render";
import { LoginPage } from "../features/login/LoginPage";
import { initTheme } from "../lib/theme";

// Apply the OS theme before React mounts so the first paint is already correct
// (no flash of dark on a light desktop).
initTheme();

// "none": nobody is signed in yet. whoami would answer 401 and the customer
// roster is not a question an unauthenticated page may ask, so this entry
// hydrates no scope and shows no scope banner.
renderApp(<LoginPage />, "the login page", { tenantScope: "none" });
