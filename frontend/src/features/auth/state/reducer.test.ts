import { describe, expect, it } from "vitest";

import type { LoginChallenge, Principal, SessionOut } from "../types";
import {
  initialState,
  reducer,
  toAuthError,
  type AuthError,
  type AuthState,
} from "./reducer";

const desafio: LoginChallenge = {
  challenge_id: "d-1",
  mfa_required: true,
  method_name: "vpg-totp",
  expires_in_seconds: 180,
  message: "falta el codigo",
  totp_status: "pending",
  enrollment_id: "e-1",
};

const sesion: SessionOut = {
  api_session: "opaca",
  token_type: "Bearer",
  user_id: "u-1",
  username: "ada.admin",
  role_codes: ["admin"],
  entity_id: "e-1",
  vault_policies: ["default"],
  expires_at: "2026-10-09T12:00:00Z",
};

const principal: Principal = {
  user_id: "u-1",
  username: "ada.admin",
  role_codes: ["admin"],
  entity_id: "e-1",
  vault_policies: ["default"],
  mfa_age_seconds: 3,
  expires_at: "2026-10-09T12:00:00Z",
};

const fallo: AuthError = {
  message: "no",
  code: "mfa_failed",
  status: 401,
  requestId: null,
  retryAfterSeconds: null,
  fields: [],
  context: {},
};

function conDesafio(): AuthState {
  return reducer(initialState, { type: "LOGIN_CHALLENGE", challenge: desafio });
}

describe("maquina de estados del acceso", () => {
  it("un desafio valido no es una sesion", () => {
    const estado = conDesafio();
    expect(estado.status).toBe("mfa_required");
    expect(estado.session).toBeNull();
    expect(estado.principal).toBeNull();
  });

  it("no relanza un login que ya esta en curso", () => {
    const enCurso = reducer(initialState, { type: "LOGIN_START" });
    const otra = reducer(enCurso, { type: "LOGIN_START" });
    expect(otra).toBe(enCurso);
  });

  it("no verifica el codigo si no hay desafio pendiente", () => {
    const sinDesafio = reducer(initialState, { type: "MFA_START" });
    expect(sinDesafio).toBe(initialState);
  });

  it("solo hay sesion tras SESSION_ESTABLISHED", () => {
    const estado = reducer(conDesafio(), {
      type: "SESSION_ESTABLISHED",
      session: sesion,
      principal,
    });
    expect(estado.status).toBe("authenticated");
    expect(estado.session).toBe("opaca");
    expect(estado.challenge).toBeNull();
  });

  it("un codigo incorrecto deja reintentar sin perder el desafio", () => {
    const estado = reducer(
      reducer(conDesafio(), { type: "MFA_START" }),
      { type: "MFA_FAILED", error: fallo },
    );
    expect(estado.status).toBe("mfa_required");
    expect(estado.challenge?.challenge_id).toBe("d-1");
  });

  it("un desafio perdido vuelve al principio y lo explica", () => {
    const estado = reducer(conDesafio(), { type: "CHALLENGE_LOST", error: fallo });
    expect(estado.status).toBe("anonymous");
    expect(estado.challenge).toBeNull();
    expect(estado.notice).toContain("caducado");
  });

  it("la autorizacion de inscripcion se retira en cuanto se usa", () => {
    const estado = reducer(conDesafio(), {
      type: "ENROLLMENT_CONSUMED",
      totpStatus: "pending",
    });
    expect(estado.challenge?.enrollment_id).toBeNull();
    // El desafio sigue vivo: inscribirse no sustituye al MFA.
    expect(estado.challenge?.challenge_id).toBe("d-1");
    expect(estado.status).toBe("mfa_required");
  });

  it("cerrar sesion borra sesion y principal", () => {
    const autenticado = reducer(conDesafio(), {
      type: "SESSION_ESTABLISHED",
      session: sesion,
      principal,
    });
    const cerrado = reducer(
      reducer(autenticado, { type: "LOGOUT_START" }),
      { type: "LOGOUT_DONE", notice: "cerrada" },
    );
    expect(cerrado.session).toBeNull();
    expect(cerrado.principal).toBeNull();
    expect(cerrado.status).toBe("anonymous");
  });

  it("perder la sesion no deja rastros autenticados", () => {
    const autenticado = reducer(conDesafio(), {
      type: "SESSION_ESTABLISHED",
      session: sesion,
      principal,
    });
    const perdida = reducer(autenticado, {
      type: "SESSION_LOST",
      notice: "caducada",
    });
    expect(perdida).toEqual({ ...initialState, notice: "caducada" });
  });

  it("un error desconocido no se disfraza de error de API", () => {
    const detalle = toAuthError(new Error("vaya"));
    expect(detalle.code).toBe("unexpected");
    expect(detalle.status).toBe(0);
  });
});
