import { renderApp } from "../app/render";
import { DevicesPage } from "../features/devices/DevicesPage";

// No tenantScope option: this entry takes the shell default, which hydrates the
// selected customer before mounting and captions it above the page. Nothing on
// this route reads the roster or names a customer of its own.
renderApp(<DevicesPage />, "the devices view");
