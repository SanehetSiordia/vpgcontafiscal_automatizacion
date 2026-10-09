import { ApiError, NetworkError, type FieldIssue } from "../../../shared/api/errors";
import type { LoginChallenge, Principal, SessionOut, TotpStatus } from "../types";

/**
 * Maquina de estados explicita del acceso. Se escribe aqui, pura y sin React,
 * porque es la parte que no debe depender de como se rendericen las pantallas.
 *
 *   anonymous ──login()──▶ logging_in ──desafio──▶ mfa_required
 *                              │                      │
 *                              └── error ──▶ anonymous (con error)
 *                                                     │
 *                             verifying_mfa ◀──codigo──┘
 *                                   │
 *                   ┌── error ──────┴──── sesion ───▶ authenticated
 *                   ▼                                      │
 *            mfa_required (reintento)          logging_out ◀┘
 *                                                     │
 *                                                     ▼
 *                                                anonymous
 *
 * Dos invariantes que el reducer hace cumplir, no la interfaz:
 *
 *  * **No hay sesion antes de `authenticated`.** Un desafio valido no es una
 *    sesion, y validar la contrasena no autentica a nadie.
 *  * **No se repite una operacion en curso.** `LOGIN_START` en `logging_in` y
 *    `MFA_START` en `verifying_mfa` se ignoran, asi que ni un doble clic ni un
 *    doble efecto de StrictMode pueden lanzar dos peticiones.
 */
export type AuthStatus =
  | "anonymous"
  | "logging_in"
  | "mfa_required"
  | "verifying_mfa"
  | "authenticated"
  | "logging_out";

export interface AuthError {
  message: string;
  code: string;
  status: number;
  requestId: string | null;
  retryAfterSeconds: number | null;
  fields: FieldIssue[];
  /** Datos no sensibles del backend (p. ej. `operation_id` de un 409). */
  context: Record<string, unknown>;
}

export interface AuthState {
  status: AuthStatus;
  /** Desafio vivo. Solo en `mfa_required` y `verifying_mfa`. */
  challenge: LoginChallenge | null;
  /** Identificador opaco de sesion. SOLO en memoria. */
  session: string | null;
  principal: Principal | null;
  expiresAt: string | null;
  error: AuthError | null;
  /** Aviso informativo, no un error: sesion caducada, cierre sin confirmar. */
  notice: string | null;
}

export const initialState: AuthState = {
  status: "anonymous",
  challenge: null,
  session: null,
  principal: null,
  expiresAt: null,
  error: null,
  notice: null,
};

export type AuthAction =
  | { type: "LOGIN_START" }
  | { type: "LOGIN_CHALLENGE"; challenge: LoginChallenge }
  | { type: "LOGIN_FAILED"; error: AuthError }
  | { type: "MFA_START" }
  | { type: "MFA_FAILED"; error: AuthError }
  | { type: "CHALLENGE_LOST"; error: AuthError }
  | { type: "ENROLLMENT_CONSUMED"; totpStatus: TotpStatus }
  | { type: "SESSION_ESTABLISHED"; session: SessionOut; principal: Principal }
  | { type: "LOGOUT_START" }
  | { type: "LOGOUT_DONE"; notice: string | null }
  | { type: "SESSION_LOST"; notice: string }
  | { type: "BACK_TO_LOGIN" }
  | { type: "CLEAR_FEEDBACK" };

export function toAuthError(error: unknown): AuthError {
  if (error instanceof ApiError) {
    return {
      message: error.message,
      code: error.code,
      status: error.status,
      requestId: error.requestId || null,
      retryAfterSeconds: error.retryAfterSeconds,
      fields: error.fields,
      context: error.context,
    };
  }
  if (error instanceof NetworkError) {
    return {
      message: error.message,
      code: "network_error",
      status: 0,
      requestId: null,
      retryAfterSeconds: null,
      fields: [],
      context: {},
    };
  }
  return {
    message: "Ha ocurrido un error inesperado. Vuelve a intentarlo.",
    code: "unexpected",
    status: 0,
    requestId: null,
    retryAfterSeconds: null,
    fields: [],
    context: {},
  };
}

export function reducer(state: AuthState, action: AuthAction): AuthState {
  switch (action.type) {
    case "LOGIN_START":
      if (state.status === "logging_in") return state;
      return { ...initialState, status: "logging_in" };

    case "LOGIN_CHALLENGE":
      // Llega un desafio, NO una sesion: `session` sigue nula a proposito.
      return {
        ...initialState,
        status: "mfa_required",
        challenge: action.challenge,
      };

    case "LOGIN_FAILED":
      return { ...initialState, status: "anonymous", error: action.error };

    case "MFA_START":
      if (state.status !== "mfa_required") return state;
      return { ...state, status: "verifying_mfa", error: null, notice: null };

    case "MFA_FAILED":
      // El desafio de Vault ya se consumio, pero el usuario puede reintentar
      // desde el mismo sitio si el backend lo permite; si no, CHALLENGE_LOST.
      return { ...state, status: "mfa_required", error: action.error };

    case "CHALLENGE_LOST":
      return {
        ...initialState,
        status: "anonymous",
        error: action.error,
        notice: "El desafío ha caducado o se ha consumido: repite el acceso.",
      };

    case "ENROLLMENT_CONSUMED": {
      if (state.challenge === null) return state;
      // La autorizacion es de un solo uso: se retira del estado en cuanto se
      // usa, para que la interfaz no pueda volver a pedirla.
      const challenge: LoginChallenge = {
        ...state.challenge,
        enrollment_id: null,
        totp_status: action.totpStatus,
      };
      return { ...state, challenge };
    }

    case "SESSION_ESTABLISHED":
      return {
        status: "authenticated",
        challenge: null,
        session: action.session.api_session,
        principal: action.principal,
        expiresAt: action.session.expires_at,
        error: null,
        notice: null,
      };

    case "LOGOUT_START":
      if (state.status !== "authenticated") return state;
      return { ...state, status: "logging_out", error: null, notice: null };

    case "LOGOUT_DONE":
      return { ...initialState, notice: action.notice };

    case "SESSION_LOST":
      return { ...initialState, notice: action.notice };

    case "BACK_TO_LOGIN":
      return { ...initialState };

    case "CLEAR_FEEDBACK":
      return { ...state, error: null, notice: null };

    default:
      return state;
  }
}
