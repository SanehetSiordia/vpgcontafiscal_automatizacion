import { API_PREFIX } from "../config/env";
import { ApiError, type ApiErrorBody, NetworkError } from "./errors";

/**
 * Cliente HTTP unico y tipado. Cuatro reglas que se cumplen aqui y no en cada
 * pantalla, para que no haya una excepcion por descuido:
 *
 *  1. **El Bearer solo viaja si se pide.** `login`, `mfa/verify` y
 *     `enrollment/totp` no llevan cabecera de autorizacion: no hay sesion
 *     todavia. Se pasa `session` solo en lo que de verdad la necesita.
 *  2. **No hay reintentos automaticos.** Ni en login, ni en MFA, ni en
 *     inscripcion o reset, ni en logout. Una respuesta incierta no se repite
 *     sola: podria consumir un desafio o emitir una segunda semilla.
 *  3. **Nada se registra.** No hay `console.*` en este archivo. El dato de
 *     diagnostico que se conserva es `request_id`, que no es sensible.
 *  4. **Cancelacion explicita.** Cada llamada acepta un `AbortSignal`, para que
 *     al desmontar un componente no quede una peticion escribiendo en estado
 *     que ya no existe.
 */

export interface RequestOptions {
  /** Identificador opaco de sesion. Se envia como `Authorization: Bearer`. */
  session?: string | null;
  signal?: AbortSignal;
  /** Cabeceras extra ya saneadas por quien llama (p. ej. X-VPG-MFA-Proof). */
  headers?: Record<string, string>;
}

const JSON_TYPE = "application/json";

function buildHeaders(
  body: unknown,
  options: RequestOptions,
): Record<string, string> {
  const headers: Record<string, string> = { Accept: JSON_TYPE };
  if (body !== undefined) headers["Content-Type"] = JSON_TYPE;
  if (options.session) headers["Authorization"] = `Bearer ${options.session}`;
  return { ...headers, ...(options.headers ?? {}) };
}

function retryAfterOf(response: Response): number | null {
  const raw = response.headers.get("Retry-After");
  if (!raw) return null;
  const seconds = Number.parseInt(raw, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

async function parseError(response: Response): Promise<ApiError> {
  const retryAfterSeconds = retryAfterOf(response);
  let body: Partial<ApiErrorBody> | null = null;
  try {
    const text = await response.text();
    body = text ? (JSON.parse(text) as Partial<ApiErrorBody>) : null;
  } catch {
    body = null;
  }

  // Un error de API que no trae el cuerpo esperado casi siempre significa que
  // respondio algo que NO es la API (el proxy, una pagina de error). Se dice
  // asi en vez de fingir un codigo de dominio.
  if (!body || typeof body.code !== "string") {
    return new ApiError({
      status: response.status,
      code: "respuesta_no_reconocida",
      message:
        `El servicio respondio ${response.status} sin el formato de error ` +
        "esperado. Si se repite, revisa el proxy y el servicio de usuarios.",
      retryAfterSeconds,
    });
  }

  return new ApiError({
    status: response.status,
    code: body.code,
    message:
      typeof body.message === "string" && body.message
        ? body.message
        : `El servicio respondio ${response.status}.`,
    requestId: typeof body.request_id === "string" ? body.request_id : "",
    context:
      typeof body.context === "object" && body.context !== null
        ? (body.context as Record<string, unknown>)
        : {},
    retryAfterSeconds,
  });
}

async function send(
  method: string,
  path: string,
  body: unknown,
  options: RequestOptions,
): Promise<Response> {
  const init: RequestInit = {
    method,
    headers: buildHeaders(body, options),
    // Mismo origen y sin cookies: la sesion es una cabecera, no una cookie.
    credentials: "omit",
    cache: "no-store",
    redirect: "error",
  };
  if (body !== undefined) init.body = JSON.stringify(body);
  if (options.signal) init.signal = options.signal;

  try {
    return await fetch(`${API_PREFIX}${path}`, init);
  } catch (error) {
    const aborted =
      error instanceof DOMException && error.name === "AbortError";
    if (aborted) throw new NetworkError("Peticion cancelada.", true);
    throw new NetworkError(
      "No se pudo contactar con el servicio de usuarios. Comprueba la " +
        "conexion y vuelve a intentarlo: no se ha reintentado solo.",
    );
  }
}

/** Peticion con cuerpo JSON de respuesta. */
export async function requestJson<T>(
  method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE",
  path: string,
  body?: unknown,
  options: RequestOptions = {},
): Promise<T> {
  const response = await send(method, path, body, options);
  if (!response.ok) throw await parseError(response);

  const text = await response.text();
  if (!text) {
    throw new ApiError({
      status: response.status,
      code: "respuesta_vacia",
      message: `El servicio respondio ${response.status} sin cuerpo.`,
    });
  }
  return JSON.parse(text) as T;
}

/**
 * Peticion sin cuerpo de respuesta (204).
 *
 * El 204 **no se parsea**: no trae JSON y pedirselo seria un error inventado.
 * El 401 se considera "ya no habia sesion", que para un logout es exito desde
 * el punto de vista del cliente.
 */
export async function requestNoContent(
  method: "POST" | "DELETE",
  path: string,
  options: RequestOptions = {},
): Promise<{ status: number }> {
  const response = await send(method, path, undefined, options);
  if (response.status === 204 || response.status === 401) {
    return { status: response.status };
  }
  if (!response.ok) throw await parseError(response);
  return { status: response.status };
}
