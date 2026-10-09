import { describe, expect, it } from "vitest";

import { API_PREFIX } from "../shared/config/env";
import openapi from "./openapi.user-mgmt.json";
import { desafio, principal, sesion } from "./httpDouble";

/**
 * Contraste contra el OpenAPI **real** de user-mgmt-service.
 *
 * El documento de `openapi.user-mgmt.json` no está escrito a mano: lo captura
 * `scripts/frontend/refresh-openapi.sh` del servicio en marcha. Estas pruebas
 * comparan con él las rutas, los campos y los ejemplos que usa el frontend, de
 * modo que un cambio de contrato rompa aquí y no en el navegador.
 *
 * Lo que NO demuestra: que el servicio en marcha se comporte como dice su
 * documento. Eso lo comprueban `scripts/frontend/smoke-frontend.sh` y el
 * recorrido manual del README.
 */
type Esquema = {
  properties?: Record<string, unknown>;
  required?: string[];
  example?: Record<string, unknown>;
};

const documento = openapi as unknown as {
  info: { version: string };
  paths: Record<string, Record<string, unknown>>;
  components: { schemas: Record<string, Esquema> };
};

/** El prefijo del navegador es el del backend con `/api` delante. */
const PREFIJO_BACKEND = API_PREFIX.replace(/^\/api/, "");

function ruta(sufijo: string): Record<string, unknown> {
  const clave = `${PREFIJO_BACKEND}${sufijo}`;
  const encontrada = documento.paths[clave];
  expect(
    encontrada,
    `el OpenAPI capturado no declara ${clave}; actualiza el frontend o el documento`,
  ).toBeDefined();
  return encontrada as Record<string, unknown>;
}

function esquema(nombre: string): Esquema {
  const encontrado = documento.components.schemas[nombre];
  expect(encontrado, `falta el esquema ${nombre} en el OpenAPI`).toBeDefined();
  return encontrado as Esquema;
}

function propiedades(nombre: string): string[] {
  return Object.keys(esquema(nombre).properties ?? {});
}

describe("el prefijo que llama el navegador", () => {
  it("es el del backend con /api por delante, para que Nginx lo reescriba", () => {
    expect(API_PREFIX).toBe("/api/user_mgmt/v1");
    expect(PREFIJO_BACKEND).toBe("/user_mgmt/v1");
  });
});

describe("rutas de autenticación", () => {
  it("las cuatro de auth existen con sus métodos", () => {
    expect(ruta("/auth/login")).toHaveProperty("post");
    expect(ruta("/auth/mfa/verify")).toHaveProperty("post");
    expect(ruta("/auth/logout")).toHaveProperty("post");
    expect(ruta("/auth/me")).toHaveProperty("get");
  });

  it("la inscripción inicial propia existe como POST", () => {
    expect(ruta("/auth/enrollment/totp")).toHaveProperty("post");
  });

  it("el logout declara 204 y 401, que es como los trata el cliente", () => {
    const logout = ruta("/auth/logout")["post"] as {
      responses: Record<string, unknown>;
    };
    expect(Object.keys(logout.responses)).toContain("204");
    expect(Object.keys(logout.responses)).toContain("401");
  });

  it("las rutas de la herramienta administrativa existen con su método", () => {
    expect(ruta("/user/{user_id}")).toHaveProperty("get");
    expect(ruta("/user/{user_id}/vault/provision")).toHaveProperty("post");
    expect(ruta("/user/{user_id}/mfa/reset")).toHaveProperty("post");
  });

  it("el GET de un empleado no tiene POST oculto que genere semillas", () => {
    expect(ruta("/user/{user_id}")).not.toHaveProperty("post");
  });
});

describe("cuerpos de entrada", () => {
  it("LoginRequest pide exactamente username y password", () => {
    expect(propiedades("LoginRequest").sort()).toEqual(["password", "username"]);
    expect(esquema("LoginRequest").required?.sort()).toEqual([
      "password",
      "username",
    ]);
  });

  it("MfaVerifyRequest pide challenge_id y code", () => {
    expect(propiedades("MfaVerifyRequest").sort()).toEqual([
      "challenge_id",
      "code",
    ]);
  });

  it("SelfEnrollmentRequest pide solo la autorización", () => {
    expect(propiedades("SelfEnrollmentRequest")).toEqual(["enrollment_id"]);
    expect(esquema("SelfEnrollmentRequest").required).toEqual(["enrollment_id"]);
  });

  it("VaultProvisionRequest solo exige la contraseña inicial", () => {
    expect(esquema("VaultProvisionRequest").required).toEqual([
      "initial_password",
    ]);
    expect(propiedades("VaultProvisionRequest")).toContain("vault_username");
  });

  it("MfaResetRequest exige confirmación y motivo", () => {
    expect(propiedades("MfaResetRequest").sort()).toEqual(["confirm", "reason"]);
  });
});

describe("cuerpos de salida", () => {
  it("LoginChallenge trae el estado histórico y la autorización", () => {
    const campos = propiedades("LoginChallenge");
    expect(campos).toContain("challenge_id");
    expect(campos).toContain("totp_status");
    expect(campos).toContain("enrollment_id");
    // Y sigue sin traer sesión: eso es el invariante del paso 1.
    expect(campos).not.toContain("api_session");
  });

  it("SessionOut trae la sesión opaca y nada de Vault que no toque", () => {
    const campos = propiedades("SessionOut");
    expect(campos).toContain("api_session");
    expect(campos).toContain("role_codes");
    expect(campos).not.toContain("vault_token");
    expect(campos).not.toContain("client_token");
  });

  it("SelfEnrollmentOut trae el URI y el estado sin cambiar", () => {
    expect(propiedades("SelfEnrollmentOut").sort()).toEqual([
      "totp_enrollment_uri",
      "totp_status",
      "username",
      "warning",
    ]);
  });

  it("EnrollmentOut puede venir sin URI, y por eso el tipo lo admite nulo", () => {
    const campos = propiedades("EnrollmentOut");
    expect(campos).toContain("totp_enrollment_uri");
    expect(esquema("EnrollmentOut").required ?? []).not.toContain(
      "totp_enrollment_uri",
    );
  });

  it("VaultLinkOut expone estado y fechas, nunca la semilla", () => {
    const campos = propiedades("VaultLinkOut");
    expect(campos).toContain("totp_status");
    expect(campos).toContain("totp_generated_at");
    expect(campos.some((c) => c.includes("secret") || c.includes("uri"))).toBe(
      false,
    );
  });

  it("ErrorDetail es el cuerpo de error que parsea el cliente", () => {
    expect(propiedades("ErrorDetail").sort()).toEqual([
      "code",
      "context",
      "message",
      "request_id",
    ]);
  });
});

describe("limitaciones conocidas del contrato", () => {
  it("/auth/me no publica esquema: su tipo se escribió leyendo el código", () => {
    const me = ruta("/auth/me")["get"] as {
      responses: Record<string, { content?: Record<string, { schema?: unknown }> }>;
    };
    const esquemaRespuesta = me.responses["200"]?.content?.["application/json"]
      ?.schema as Record<string, unknown> | undefined;

    // El backend lo declara con `response_model=dict`, asi que aqui solo hay
    // un objeto libre. Si algun dia se tipa, esta prueba fallara: entonces hay
    // que sustituir el tipo Principal por el esquema real.
    expect(esquemaRespuesta).toMatchObject({ type: "object" });
    expect(esquemaRespuesta).not.toHaveProperty("properties");
  });
});

describe("los ejemplos del doble HTTP son los del contrato", () => {
  it("el desafío del doble tiene los campos del esquema", () => {
    const campos = propiedades("LoginChallenge");
    for (const clave of Object.keys(
      desafio({ totp_status: "pending", enrollment_id: "x" }) as object,
    )) {
      expect(campos, `el doble envía ${clave}, que el esquema no declara`).toContain(
        clave,
      );
    }
  });

  it("la sesión del doble tiene los campos del esquema", () => {
    const campos = propiedades("SessionOut");
    for (const clave of Object.keys(sesion() as object)) {
      expect(campos).toContain(clave);
    }
  });

  it("el ejemplo del propio OpenAPI encaja con el tipo del frontend", () => {
    const ejemplo = esquema("SessionOut").example ?? {};
    for (const clave of Object.keys(ejemplo)) {
      expect(Object.keys(sesion() as object)).toContain(clave);
    }
  });

  it("el principal del doble cubre lo que lee la interfaz", () => {
    const campos = Object.keys(principal() as object);
    for (const clave of [
      "user_id",
      "username",
      "role_codes",
      "entity_id",
      "vault_policies",
      "mfa_age_seconds",
      "expires_at",
    ]) {
      expect(campos).toContain(clave);
    }
  });

  it("el documento capturado es del servicio de esta etapa", () => {
    expect(documento.info.version).toMatch(/^0\.\d+\.\d+$/);
  });
});
