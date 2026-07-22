import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { LoginPage } from "../features/login/LoginPage";

describe("LoginPage password policy", () => {
  it("shows every requirement and gates Sign in until the policy is met", () => {
    // No theme prop: the page derives its theme from the OS (src/lib/theme.ts).
    const { container } = render(<LoginPage />);

    // The five policy requirements are rendered for the operator.
    expect(screen.getByText("At least 14 characters")).toBeTruthy();
    expect(screen.getByText("At least one uppercase letter")).toBeTruthy();
    expect(screen.getByText("At least one lowercase letter")).toBeTruthy();
    expect(screen.getByText("At least 3 numbers")).toBeTruthy();
    expect(screen.getByText("At least 3 special characters")).toBeTruthy();

    const signIn = screen.getByRole("button", { name: /sign in/i }) as HTMLButtonElement;
    const pass = container.querySelector('input[name="pass"]') as HTMLInputElement;

    // Empty → disabled.
    expect(signIn.disabled).toBe(true);

    // A weak password (the retired demo credential) keeps it disabled.
    fireEvent.change(pass, { target: { value: "ebpf-soc-demo" } });
    expect(signIn.disabled).toBe(true);

    // A compliant password enables submit and marks every requirement met.
    fireEvent.change(pass, { target: { value: "A2pl9386&CCjp&@4U@15" } });
    expect(signIn.disabled).toBe(false);
    const rows = container.querySelectorAll('#password-policy li[data-met]');
    expect(rows.length).toBe(5);
    rows.forEach((row) => expect(row.getAttribute("data-met")).toBe("true"));
  });
});
