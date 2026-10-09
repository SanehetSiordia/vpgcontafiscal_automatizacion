import { render, type RenderResult } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { StrictMode, type ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

import { App } from "../app/App";
import {
  AuthContext,
  type AuthContextValue,
} from "../features/auth/state/AuthContext";
import { AuthProvider } from "../features/auth/state/AuthProvider";
import { initialState } from "../features/auth/state/reducer";
import type { Principal } from "../features/auth/types";

/**
 * Monta la aplicación completa con el router en memoria.
 *
 * Va dentro de `StrictMode` a propósito: si algún efecto repitiera un login,
 * una verificación, una inscripción o un reset, el doble HTTP registraría dos
 * llamadas y las pruebas que cuentan peticiones lo detectarían.
 */
export function montarApp(ruta = "/login"): RenderResult & {
  usuario: ReturnType<typeof userEvent.setup>;
} {
  const resultado = render(
    <StrictMode>
      <MemoryRouter
        initialEntries={[ruta]}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </StrictMode>,
  );
  return { ...resultado, usuario: userEvent.setup() };
}

/**
 * Monta una pantalla **con sesión ya establecida**, inyectando el contexto.
 *
 * Se usa para las pantallas que solo existen tras el acceso: repetir el login
 * de dos pasos en cada caso no probaría nada nuevo y escondería lo que se
 * quiere comprobar. El proveedor real se prueba aparte, en las pruebas del
 * acceso y del reducer.
 */
export function montarConSesion(
  ui: ReactElement,
  opciones: {
    roles?: string[];
    session?: string;
    reportAuthFailure?: AuthContextValue["reportAuthFailure"];
  } = {},
): RenderResult & { usuario: ReturnType<typeof userEvent.setup> } {
  const principal: Principal = {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "ada.admin",
    role_codes: opciones.roles ?? ["admin"],
    entity_id: "22222222-2222-4222-8222-222222222222",
    vault_policies: ["default", "vpg-secrets-admin"],
    mfa_age_seconds: 5,
    expires_at: "2026-10-09T12:00:00Z",
  };

  const valor: AuthContextValue = {
    state: {
      ...initialState,
      status: "authenticated",
      session: opciones.session ?? "sesion-opaca-de-prueba",
      principal,
      expiresAt: principal.expires_at,
    },
    signIn: vi.fn(async () => undefined),
    submitCode: vi.fn(async () => undefined),
    enrollTotp: vi.fn(),
    signOut: vi.fn(async () => undefined),
    backToLogin: vi.fn(),
    clearFeedback: vi.fn(),
    reportAuthFailure: opciones.reportAuthFailure ?? vi.fn(),
  };

  const resultado = render(
    <StrictMode>
      <MemoryRouter
        initialEntries={["/configuracion-totp"]}
        future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      >
        <AuthContext.Provider value={valor}>{ui}</AuthContext.Provider>
      </MemoryRouter>
    </StrictMode>,
  );
  return { ...resultado, usuario: userEvent.setup() };
}
