import { renderApp } from "../app/render";
import { applyLoginTheme, LoginPage, readLoginTheme } from "../features/login/LoginPage";

const initialTheme = readLoginTheme();
applyLoginTheme(initialTheme);

renderApp(<LoginPage initialTheme={initialTheme} />);
