import { requestJson, requestNoContent } from "../../shared/api/http";
import type {
  LoginChallenge,
  LoginRequest,
  MfaVerifyRequest,
  Principal,
  SelfEnrollmentOut,
  SessionOut,
} from "./types";
import { toPrincipal } from "./types";

/**
 * Los cuatro endpoints de autenticacion, mas la inscripcion inicial.
 *
 * Que endpoint lleva Bearer y que endpoint no, no es un detalle: `login`,
 * `verifyMfa` y `selfEnrollTotp` ocurren **antes** de que exista sesion, asi
 * que mandar una cabecera de autorizacion ahi solo podria filtrar una sesion
 * anterior.
 */

export function login(
  payload: LoginRequest,
  signal?: AbortSignal,
): Promise<LoginChallenge> {
  return requestJson<LoginChallenge>("POST", "/auth/login", payload, { signal });
}

export function verifyMfa(
  payload: MfaVerifyRequest,
  signal?: AbortSignal,
): Promise<SessionOut> {
  return requestJson<SessionOut>("POST", "/auth/mfa/verify", payload, { signal });
}

export function selfEnrollTotp(
  enrollmentId: string,
  signal?: AbortSignal,
): Promise<SelfEnrollmentOut> {
  return requestJson<SelfEnrollmentOut>(
    "POST",
    "/auth/enrollment/totp",
    { enrollment_id: enrollmentId },
    { signal },
  );
}

export async function me(
  session: string,
  signal?: AbortSignal,
): Promise<Principal> {
  const raw = await requestJson<unknown>("GET", "/auth/me", undefined, {
    session,
    signal,
  });
  return toPrincipal(raw);
}

/**
 * Cierre de sesion. Devuelve el estado para que la interfaz pueda distinguir
 * "revocada ahora" (204) de "ya no existia" (401).
 *
 * Si falla la red, el llamador borra el estado local igualmente, pero **no**
 * puede afirmar que el servidor haya revocado nada: el token de Vault vivira
 * hasta su TTL. La pantalla lo dice con esas palabras.
 */
export function logout(
  session: string,
  signal?: AbortSignal,
): Promise<{ status: number }> {
  return requestNoContent("POST", "/auth/logout", { session, signal });
}
