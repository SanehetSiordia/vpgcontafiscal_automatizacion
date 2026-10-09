import { describe, expect, it } from "vitest";

import { instalarHttpDoble, instalarRedCaida, PREFIJO } from "../../test/httpDouble";
import { ApiError, NetworkError } from "./errors";
import { requestJson, requestNoContent } from "./http";

describe("cliente HTTP", () => {
  it("no manda Authorization si no se le da sesion", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/login`, { status: 200, body: { ok: true } });

    await requestJson("POST", "/auth/login", { username: "ada.admin" });

    const llamada = http.ultima("POST", `${PREFIJO}/auth/login`);
    expect(llamada?.headers).not.toHaveProperty("Authorization");
  });

  it("manda Authorization solo cuando se le pasa la sesion", async () => {
    const http = instalarHttpDoble();
    http.cuando("GET", `${PREFIJO}/auth/me`, { status: 200, body: { username: "ada" } });

    await requestJson("GET", "/auth/me", undefined, { session: "opaca" });

    expect(http.ultima("GET", `${PREFIJO}/auth/me`)?.headers["Authorization"]).toBe(
      "Bearer opaca",
    );
  });

  it("usa rutas relativas del mismo origen", async () => {
    const http = instalarHttpDoble();
    http.cuando("GET", `${PREFIJO}/auth/me`, { status: 200, body: {} });

    await requestJson("GET", "/auth/me", undefined, { session: "x" });

    const url = http.llamadas[0]?.url ?? "";
    expect(url.startsWith("/api/user_mgmt/v1")).toBe(true);
    expect(url).not.toContain("://");
  });

  it("trata el 204 sin intentar parsear JSON", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/logout`, { status: 204 });

    await expect(
      requestNoContent("POST", "/auth/logout", { session: "opaca" }),
    ).resolves.toEqual({ status: 204 });
  });

  it("considera el 401 del logout como sesion ya cerrada", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/logout`, {
      status: 401,
      body: { code: "unauthenticated", message: "no hay sesion", request_id: "r" },
    });

    await expect(
      requestNoContent("POST", "/auth/logout", { session: "opaca" }),
    ).resolves.toEqual({ status: 401 });
  });

  it("conserva code, request_id y campos del ErrorDetail real", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/login`, {
      status: 422,
      body: {
        code: "validation_error",
        message: "el cuerpo no supera la validacion",
        request_id: "abc123",
        context: { fields: [{ field: "username", reason: "username invalido" }] },
      },
    });

    const fallo = await requestJson("POST", "/auth/login", {}).catch((e) => e);

    expect(fallo).toBeInstanceOf(ApiError);
    expect((fallo as ApiError).code).toBe("validation_error");
    expect((fallo as ApiError).requestId).toBe("abc123");
    expect((fallo as ApiError).fields).toEqual([
      { field: "username", reason: "username invalido" },
    ]);
  });

  it("lee Retry-After del 429", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/mfa/verify`, {
      status: 429,
      headers: { "Retry-After": "42" },
      body: { code: "rate_limited", message: "demasiados", request_id: "r" },
    });

    const fallo = (await requestJson("POST", "/auth/mfa/verify", {}).catch(
      (e) => e,
    )) as ApiError;

    expect(fallo.retryAfterSeconds).toBe(42);
  });

  it("no reintenta: una peticion fallida es una sola peticion", async () => {
    const http = instalarHttpDoble();
    http.cuando("POST", `${PREFIJO}/auth/login`, {
      status: 503,
      body: { code: "upstream_unavailable", message: "Vault sellado", request_id: "r" },
    });

    await requestJson("POST", "/auth/login", {}).catch(() => undefined);

    expect(http.contar("POST", `${PREFIJO}/auth/login`)).toBe(1);
  });

  it("distingue la red caida de una respuesta del servicio", async () => {
    instalarRedCaida();

    const fallo = await requestJson("GET", "/auth/me", undefined, {
      session: "x",
    }).catch((e) => e);

    expect(fallo).toBeInstanceOf(NetworkError);
    expect(fallo).not.toBeInstanceOf(ApiError);
  });

  it("no finge un codigo de dominio si la respuesta no es de la API", async () => {
    const http = instalarHttpDoble();
    http.cuando("GET", `${PREFIJO}/auth/me`, { status: 502, body: "<html>" });

    const fallo = (await requestJson("GET", "/auth/me", undefined, {
      session: "x",
    }).catch((e) => e)) as ApiError;

    expect(fallo.code).toBe("respuesta_no_reconocida");
    expect(fallo.status).toBe(502);
  });
});
