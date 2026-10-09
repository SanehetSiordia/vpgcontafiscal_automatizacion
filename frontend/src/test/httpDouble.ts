import { vi } from "vitest";

/**
 * Doble HTTP explícito.
 *
 * Explícito significa dos cosas:
 *
 *  * cada ruta se declara en la prueba, con su cuerpo y su estado reales; y
 *  * una petición que no coincida con ninguna ruta declarada **falla la
 *    prueba** en vez de devolver un 200 vacío. Así una llamada de más (un
 *    efecto repetido, un reintento automático) se ve en cuanto aparece.
 *
 * Los cuerpos que se escriben aquí son los del contrato real de
 * user-mgmt-service. Que coincidan con el OpenAPI publicado lo comprueba
 * `src/test/contract.test.ts`, que lee el documento capturado del servicio.
 */
export interface RespuestaDoble {
  status: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export interface LlamadaRegistrada {
  method: string;
  url: string;
  body: unknown;
  headers: Record<string, string>;
}

interface Ruta {
  method: string;
  url: string;
  respuestas: RespuestaDoble[];
}

export interface HttpDoble {
  cuando(method: string, url: string, respuesta: RespuestaDoble | RespuestaDoble[]): void;
  readonly llamadas: LlamadaRegistrada[];
  contar(method: string, url: string): number;
  ultima(method: string, url: string): LlamadaRegistrada | undefined;
}

export function instalarHttpDoble(): HttpDoble {
  const rutas: Ruta[] = [];
  const llamadas: LlamadaRegistrada[] = [];

  const implementacion = async (
    entrada: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = typeof entrada === "string" ? entrada : entrada.toString();
    const method = (init?.method ?? "GET").toUpperCase();
    const headers = Object.fromEntries(
      Object.entries((init?.headers ?? {}) as Record<string, string>),
    );
    let body: unknown = undefined;
    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    }
    llamadas.push({ method, url, body, headers });

    const ruta = rutas.find((r) => r.method === method && r.url === url);
    if (ruta === undefined) {
      throw new Error(
        `Peticion no declarada en el doble: ${method} ${url}. ` +
          "Si la aplicacion deberia hacerla, declarala con cuando(); si no, " +
          "es una llamada de mas.",
      );
    }
    const respuesta =
      ruta.respuestas.length > 1
        ? (ruta.respuestas.shift() as RespuestaDoble)
        : (ruta.respuestas[0] as RespuestaDoble);

    const cuerpo =
      respuesta.body === undefined ? "" : JSON.stringify(respuesta.body);
    return new Response(cuerpo === "" ? null : cuerpo, {
      status: respuesta.status,
      headers: {
        "Content-Type": "application/json",
        ...(respuesta.headers ?? {}),
      },
    });
  };

  vi.stubGlobal("fetch", vi.fn(implementacion));

  return {
    cuando(method, url, respuesta) {
      rutas.push({
        method: method.toUpperCase(),
        url,
        respuestas: Array.isArray(respuesta) ? [...respuesta] : [respuesta],
      });
    },
    llamadas,
    contar(method, url) {
      const buscado = method.toUpperCase();
      return llamadas.filter((l) => l.method === buscado && l.url === url).length;
    },
    ultima(method, url) {
      const buscado = method.toUpperCase();
      return [...llamadas].reverse().find((l) => l.method === buscado && l.url === url);
    },
  };
}

/** Simula una red que no responde (no es un 503: el servidor no dijo nada). */
export function instalarRedCaida(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }),
  );
}

// --- cuerpos del contrato real, reutilizados por varias pruebas ------------

export const PREFIJO = "/api/user_mgmt/v1";

export function desafio(extra: Record<string, unknown> = {}): unknown {
  return {
    challenge_id: "desafio-de-prueba-0001",
    mfa_required: true,
    method_name: "vpg-totp",
    expires_in_seconds: 180,
    message:
      "Login incompleto: todavia no hay sesion. Envia el codigo TOTP a " +
      "/auth/mfa/verify antes de que caduque el desafio.",
    ...extra,
  };
}

export function sesion(extra: Record<string, unknown> = {}): unknown {
  return {
    api_session: "sesion-opaca-de-prueba",
    token_type: "Bearer",
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "ada.admin",
    role_codes: ["admin"],
    entity_id: "22222222-2222-4222-8222-222222222222",
    vault_policies: ["default", "vpg-secrets-admin"],
    expires_at: "2026-10-09T12:00:00Z",
    ...extra,
  };
}

export function principal(extra: Record<string, unknown> = {}): unknown {
  return {
    user_id: "11111111-1111-4111-8111-111111111111",
    username: "ada.admin",
    role_codes: ["admin"],
    entity_id: "22222222-2222-4222-8222-222222222222",
    vault_policies: ["default", "vpg-secrets-admin"],
    mfa_age_seconds: 4,
    expires_at: "2026-10-09T12:00:00Z",
    ...extra,
  };
}

export function error(
  code: string,
  message: string,
  context: Record<string, unknown> = {},
): unknown {
  return {
    code,
    message,
    request_id: "0f9c2b8e4a7d4f1b9c3e5a6d7b8c9e01",
    context,
  };
}

export const URI_OTPAUTH =
  "otpauth://totp/VPG%20Contadores:ada.admin?secret=JBSWY3DPEHPK3PXP" +
  "&issuer=VPG%20Contadores&algorithm=SHA1&digits=6&period=30";
