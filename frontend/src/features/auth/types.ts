/**
 * Tipos de los DTO de autenticacion de user-mgmt-service.
 *
 * La correspondencia con los esquemas Pydantic reales esta tabulada en
 * readme/etapa-5-1-frontend.md. Aqui solo dos avisos que condicionan el codigo:
 *
 *  * `api_session` es un identificador **opaco**: no es un JWT y no es el token
 *    de Vault. No se descodifica, no se inspecciona y no se guarda en disco.
 *  * `GET /auth/me` esta declarado en el backend con `response_model=dict`, asi
 *    que su OpenAPI no describe campos. El tipo de abajo se escribio leyendo la
 *    implementacion (app/routers/auth.py), no el esquema, y por eso todos los
 *    campos se validan antes de usarse.
 */

/** `app/schemas/user.py::TotpStatus` */
export type TotpStatus = "pending" | "confirmed" | "reset_required" | "disabled";

/** `app/schemas/auth.py::LoginRequest` */
export interface LoginRequest {
  username: string;
  password: string;
}

/** `app/schemas/auth.py::LoginChallenge` */
export interface LoginChallenge {
  challenge_id: string;
  mfa_required: true;
  method_name: string;
  expires_in_seconds: number;
  message: string;
  /** Ampliacion 5.1: estado HISTORICO. Nulo si no hay vinculo registrado. */
  totp_status?: TotpStatus | null;
  /** Ampliacion 5.1: autorizacion de un solo uso para inscribir el TOTP propio. */
  enrollment_id?: string | null;
}

/** `app/schemas/auth.py::MfaVerifyRequest` */
export interface MfaVerifyRequest {
  challenge_id: string;
  code: string;
}

/** `app/schemas/auth.py::SessionOut` */
export interface SessionOut {
  api_session: string;
  token_type: "Bearer";
  user_id: string;
  username: string;
  role_codes: string[];
  entity_id: string;
  vault_policies: string[];
  expires_at: string;
}

/** `app/schemas/auth.py::SelfEnrollmentRequest` */
export interface SelfEnrollmentRequest {
  enrollment_id: string;
}

/** `app/schemas/auth.py::SelfEnrollmentOut` */
export interface SelfEnrollmentOut {
  username: string;
  totp_status: TotpStatus;
  totp_enrollment_uri: string;
  warning: string;
}

/** Respuesta de `GET /auth/me` (sin esquema en OpenAPI: ver nota de arriba). */
export interface Principal {
  user_id: string;
  username: string;
  role_codes: string[];
  entity_id: string;
  vault_policies: string[];
  mfa_age_seconds: number;
  expires_at: string;
}

/** Normaliza `/auth/me` sin confiar en que venga completo. */
export function toPrincipal(raw: unknown): Principal {
  const data = (typeof raw === "object" && raw !== null ? raw : {}) as Record<
    string,
    unknown
  >;
  const texts = (value: unknown): string[] =>
    Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];

  return {
    user_id: typeof data["user_id"] === "string" ? data["user_id"] : "",
    username: typeof data["username"] === "string" ? data["username"] : "",
    role_codes: texts(data["role_codes"]),
    entity_id: typeof data["entity_id"] === "string" ? data["entity_id"] : "",
    vault_policies: texts(data["vault_policies"]),
    mfa_age_seconds:
      typeof data["mfa_age_seconds"] === "number" ? data["mfa_age_seconds"] : 0,
    expires_at: typeof data["expires_at"] === "string" ? data["expires_at"] : "",
  };
}

export const ADMIN_ROLE = "admin";

export function isAdmin(principal: Principal | null): boolean {
  return principal !== null && principal.role_codes.includes(ADMIN_ROLE);
}
