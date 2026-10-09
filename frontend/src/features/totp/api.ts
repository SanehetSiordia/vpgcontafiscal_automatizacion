import { requestJson } from "../../shared/api/http";
import type {
  EnrollmentOut,
  MfaResetRequest,
  ProvisionRequest,
  UserDetail,
} from "./types";

/**
 * Los tres endpoints reales que usa la herramienta administrativa. No hay
 * búsqueda de empleados ni alta completa: esta etapa no las implementa, y una
 * pantalla que las fingiera llamaría a rutas que no existen.
 *
 * El GET es **solo lectura y sin efectos**: ni genera semillas, ni las
 * devuelve, ni cambia estados. Eso es del contrato del backend, no una promesa
 * de esta capa.
 */

export function getUser(
  session: string,
  userId: string,
  signal?: AbortSignal,
): Promise<UserDetail> {
  return requestJson<UserDetail>("GET", `/user/${userId}`, undefined, {
    session,
    signal,
  });
}

/** `POST /user/{id}/vault/provision` — solo admin, entrega el URI una vez. */
export function provisionVault(
  session: string,
  userId: string,
  payload: ProvisionRequest,
  signal?: AbortSignal,
): Promise<EnrollmentOut> {
  return requestJson<EnrollmentOut>(
    "POST",
    `/user/${userId}/vault/provision`,
    payload,
    { session, signal },
  );
}

/**
 * `POST /user/{id}/mfa/reset` — solo admin, con MFA reciente y confirmación
 * explícita. Destruye la semilla de esa persona e invalida sus sesiones.
 *
 * Nunca se llama al abrir la pantalla, ni al recibir `pending`, ni al fallar un
 * código: siempre desde una confirmación escrita a mano.
 */
export function resetMfa(
  session: string,
  userId: string,
  payload: MfaResetRequest,
  signal?: AbortSignal,
): Promise<EnrollmentOut> {
  return requestJson<EnrollmentOut>(
    "POST",
    `/user/${userId}/mfa/reset`,
    payload,
    { session, signal },
  );
}
