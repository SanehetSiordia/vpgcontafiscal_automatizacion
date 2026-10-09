/**
 * Errores de la API, con el `ErrorDetail` real de user-mgmt-service.
 *
 * El backend responde siempre `{code, message, request_id, context}`
 * (app/core/errors.py). Los 422 de Pydantic llegan por el mismo cuerpo, con
 * `context.fields = [{field, reason}]`: campo y motivo, **nunca** el valor
 * enviado. Aqui se conserva esa forma en vez de inventar otra.
 */

/** Cuerpo de error uniforme de la API. */
export interface ApiErrorBody {
  code: string;
  message: string;
  request_id: string;
  context?: Record<string, unknown>;
}

/** Un campo invalido tal como lo informa el backend. */
export interface FieldIssue {
  field: string;
  reason: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
  readonly context: Record<string, unknown>;
  /** Segundos de `Retry-After`, solo en 429. */
  readonly retryAfterSeconds: number | null;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    requestId?: string;
    context?: Record<string, unknown>;
    retryAfterSeconds?: number | null;
  }) {
    super(init.message);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.requestId = init.requestId ?? "";
    this.context = init.context ?? {};
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
  }

  /** Campos invalidos de un 422, si el backend los informo. */
  get fields(): FieldIssue[] {
    const raw = this.context["fields"];
    if (!Array.isArray(raw)) return [];
    return raw.flatMap((item) => {
      if (typeof item !== "object" || item === null) return [];
      const field = (item as Record<string, unknown>)["field"];
      const reason = (item as Record<string, unknown>)["reason"];
      if (typeof field !== "string" || typeof reason !== "string") return [];
      return [{ field, reason }];
    });
  }
}

/**
 * La peticion no llego a obtener respuesta: red caida, DNS, TLS o el proxy sin
 * upstream. No es lo mismo que un 503 del servicio, y por eso no se mezcla: un
 * 503 lo responde el backend diciendo que le falta algo, esto no dice nada.
 */
export class NetworkError extends Error {
  readonly aborted: boolean;

  constructor(message: string, aborted = false) {
    super(message);
    this.name = "NetworkError";
    this.aborted = aborted;
  }
}

/** Mensaje para la persona, en espanol y sin filtrar lo que no toca. */
export function humanMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof NetworkError) return error.message;
  return "Ha ocurrido un error inesperado. Vuelve a intentarlo.";
}

/** Identificador de la peticion, util para buscar en el log del servicio. */
export function requestIdOf(error: unknown): string | null {
  if (error instanceof ApiError && error.requestId) return error.requestId;
  return null;
}
