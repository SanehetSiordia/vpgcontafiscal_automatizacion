import type { TotpStatus } from "../auth/types";

/**
 * Subconjunto de los DTO de empleado que necesita la herramienta de
 * inscripción. Se declara solo lo que se usa: ni esta pantalla ni esta etapa
 * implementan el CRUD de empleados.
 */

/** `app/schemas/user.py::VaultLinkOut` */
export interface VaultLink {
  vault_username: string;
  vault_entity_id: string;
  totp_status: TotpStatus;
  totp_generated_at: string | null;
  totp_confirmed_at: string | null;
  last_mfa_login_at: string | null;
  notice?: string | null;
}

/** `app/schemas/user.py::UserOut`, recortado a lo que se muestra. */
export interface UserDetail {
  id: string;
  username: string;
  is_active: boolean;
  role_codes: string[];
  vault_link: VaultLink | null;
}

/** `app/schemas/auth.py::VaultProvisionRequest` */
export interface ProvisionRequest {
  initial_password: string;
  vault_username?: string;
  policy?: string;
}

/** `app/schemas/auth.py::MfaResetRequest` */
export interface MfaResetRequest {
  confirm: "RESET";
  reason: string;
}

/**
 * `app/schemas/auth.py::EnrollmentOut`.
 *
 * `totp_enrollment_uri` es opcional en el esquema real: puede venir nulo. La
 * pantalla lo trata como "no hay QR que mostrar" en vez de inventar uno.
 */
export interface EnrollmentOut {
  operation_id: string;
  user_id: string;
  vault_username: string;
  vault_entity_id: string;
  totp_status: TotpStatus;
  totp_enrollment_uri: string | null;
  warning: string;
}

/** UUID v1-v5 en minúsculas o mayúsculas, con guiones. */
export const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
