import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ProtectedRoute } from "../../auth/components/ProtectedRoute";
import {
  error,
  instalarHttpDoble,
  PREFIJO,
  URI_OTPAUTH,
  type HttpDoble,
} from "../../../test/httpDouble";
import { montarConSesion } from "../../../test/render";
import { TotpAdminPage } from "./TotpAdminPage";

const OBJETIVO = "33333333-3333-4333-8333-333333333333";
const USUARIO = `${PREFIJO}/user/${OBJETIVO}`;
const PROVISION = `${USUARIO}/vault/provision`;
const RESET = `${USUARIO}/mfa/reset`;

const EMPLEADO = {
  id: OBJETIVO,
  username: "eva.employee",
  is_active: true,
  role_codes: ["employee"],
  vault_link: {
    vault_username: "eva.employee",
    vault_entity_id: "44444444-4444-4444-8444-444444444444",
    totp_status: "pending",
    totp_generated_at: "2026-10-01T10:00:00Z",
    totp_confirmed_at: null,
    last_mfa_login_at: null,
    notice: "Estado historico: 'pending' no demuestra que no tenga autenticador.",
  },
};

function conObjetivo(): ReturnType<typeof montarConSesion> {
  return montarConSesion(<TotpAdminPage />);
}

async function escribirObjetivo(
  usuario: ReturnType<typeof montarConSesion>["usuario"],
): Promise<void> {
  await usuario.type(screen.getByLabelText("UUID del empleado"), OBJETIVO);
}

describe("acceso a la herramienta administrativa", () => {
  beforeEach(() => {
    instalarHttpDoble();
  });

  it("un empleado no entra, aunque conozca la ruta", () => {
    montarConSesion(
      <ProtectedRoute requireAdmin>
        <TotpAdminPage />
      </ProtectedRoute>,
      { roles: ["employee"] },
    );

    expect(
      screen.getByText("Esta herramienta es solo para administradores"),
    ).toBeVisible();
    expect(screen.queryByLabelText("UUID del empleado")).toBeNull();
  });

  it("un manager tampoco: provisionar no es parte de su rol", () => {
    montarConSesion(
      <ProtectedRoute requireAdmin>
        <TotpAdminPage />
      </ProtectedRoute>,
      { roles: ["manager", "employee"] },
    );

    expect(
      screen.getByText("Esta herramienta es solo para administradores"),
    ).toBeVisible();
  });

  it("un admin si entra", () => {
    montarConSesion(
      <ProtectedRoute requireAdmin>
        <TotpAdminPage />
      </ProtectedRoute>,
      { roles: ["admin"] },
    );

    expect(screen.getByLabelText("UUID del empleado")).toBeVisible();
  });
});

describe("herramienta de inscripcion TOTP", () => {
  let http: HttpDoble;

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("abrir la pantalla no consulta ni provisiona nada", () => {
    conObjetivo();

    expect(http.llamadas).toHaveLength(0);
  });

  it("rechaza un identificador que no es un UUID sin llamar al servicio", async () => {
    const { usuario } = conObjetivo();

    await usuario.type(screen.getByLabelText("UUID del empleado"), "eva.employee");
    await usuario.click(screen.getByRole("button", { name: /Consultar estado/ }));

    expect(await screen.findByText(/Escribe el UUID del empleado/)).toBeVisible();
    expect(http.llamadas).toHaveLength(0);
  });

  it("la consulta es un GET sin efectos: no genera semilla ni la devuelve", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.click(screen.getByRole("button", { name: /Consultar estado/ }));

    expect(await screen.findByText("eva.employee")).toBeVisible();
    expect(screen.getByText(/eva.employee · pending/)).toBeVisible();
    expect(http.llamadas.filter((l) => l.method !== "GET")).toHaveLength(0);
    expect(screen.queryByTitle(/Inscripción TOTP/)).toBeNull();
    expect(http.contar("GET", USUARIO)).toBe(1);
  });

  it("pending por si solo no provisiona ni reinicia nada", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.click(screen.getByRole("button", { name: /Consultar estado/ }));
    await screen.findByText("eva.employee");

    expect(http.contar("POST", PROVISION)).toBe(0);
    expect(http.contar("POST", RESET)).toBe(0);
    // Y el reset sigue deshabilitado hasta que se escriba la confirmacion.
    expect(
      screen.getByRole("button", { name: /Reiniciar el segundo factor/ }),
    ).toBeDisabled();
  });

  it("aprovisionar entrega el QR del URI real, una sola vez", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    http.cuando("POST", PROVISION, {
      status: 201,
      body: {
        operation_id: "55555555-5555-4555-8555-555555555555",
        user_id: OBJETIVO,
        vault_username: "eva.employee",
        vault_entity_id: "44444444-4444-4444-8444-444444444444",
        totp_status: "pending",
        totp_enrollment_uri: URI_OTPAUTH,
        warning: "Este URI se entrega UNA sola vez.",
      },
    });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.type(
      screen.getByLabelText("Contraseña inicial en Vault"),
      "contrasena-inicial",
    );
    await usuario.click(
      screen.getByRole("button", { name: /Aprovisionar y mostrar el QR/ }),
    );

    expect(await screen.findByTitle("Inscripción TOTP de eva.employee")).toBeInTheDocument();
    expect(screen.getByText(/Escanear código QR/)).toBeVisible();
    expect(http.contar("POST", PROVISION)).toBe(1);
    expect(http.ultima("POST", PROVISION)?.body).toEqual({
      initial_password: "contrasena-inicial",
    });
  });

  it("una respuesta sin URI no se sustituye por un QR inventado", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    http.cuando("POST", PROVISION, {
      status: 201,
      body: {
        operation_id: "55555555-5555-4555-8555-555555555555",
        user_id: OBJETIVO,
        vault_username: "eva.employee",
        vault_entity_id: "44444444-4444-4444-8444-444444444444",
        totp_status: "pending",
        totp_enrollment_uri: null,
        warning: "una sola vez",
      },
    });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.type(
      screen.getByLabelText("Contraseña inicial en Vault"),
      "contrasena-inicial",
    );
    await usuario.click(
      screen.getByRole("button", { name: /Aprovisionar y mostrar el QR/ }),
    );

    expect(await screen.findByText("Sin URI que mostrar")).toBeVisible();
    expect(screen.queryByTitle(/Inscripción TOTP/)).toBeNull();
  });

  it("un 409 parcial muestra el operation_id y no emite otra semilla", async () => {
    http.cuando("POST", PROVISION, {
      status: 409,
      body: error("partial_operation", "Vault cambio pero PostgreSQL no", {
        operation_id: "66666666-6666-4666-8666-666666666666",
      }),
    });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.type(
      screen.getByLabelText("Contraseña inicial en Vault"),
      "contrasena-inicial",
    );
    await usuario.click(
      screen.getByRole("button", { name: /Aprovisionar y mostrar el QR/ }),
    );

    expect(
      await screen.findByText("Operación parcial: hay que reconciliar"),
    ).toBeVisible();
    expect(
      screen.getByText("66666666-6666-4666-8666-666666666666"),
    ).toBeVisible();
    expect(http.contar("POST", PROVISION)).toBe(1);
  });

  it("el reset exige la palabra de confirmacion y un motivo", async () => {
    const { usuario } = conObjetivo();
    const boton = screen.getByRole("button", { name: /Reiniciar el segundo factor/ });

    await escribirObjetivo(usuario);
    expect(boton).toBeDisabled();

    await usuario.type(screen.getByLabelText("Motivo"), "dispositivo perdido");
    expect(boton).toBeDisabled();

    await usuario.type(screen.getByLabelText('Escribe "RESET" para confirmar'), "reset");
    expect(boton).toBeEnabled();
    // Nada se ha pedido todavia: hace falta el envio.
    expect(http.contar("POST", RESET)).toBe(0);
  });

  it("el reset envia el DTO real cuando se confirma", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    http.cuando("POST", RESET, {
      status: 200,
      body: {
        operation_id: "77777777-7777-4777-8777-777777777777",
        user_id: OBJETIVO,
        vault_username: "eva.employee",
        vault_entity_id: "44444444-4444-4444-8444-444444444444",
        totp_status: "reset_required",
        totp_enrollment_uri: URI_OTPAUTH,
        warning: "una sola vez",
      },
    });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.type(screen.getByLabelText("Motivo"), "dispositivo perdido");
    await usuario.type(screen.getByLabelText('Escribe "RESET" para confirmar'), "reset");
    await usuario.click(
      screen.getByRole("button", { name: /Reiniciar el segundo factor/ }),
    );

    expect(await screen.findByTitle("Inscripción TOTP de eva.employee")).toBeInTheDocument();
    expect(http.ultima("POST", RESET)?.body).toEqual({
      confirm: "RESET",
      reason: "dispositivo perdido",
    });
    expect(http.contar("POST", RESET)).toBe(1);
  });

  it("un 403 por MFA viejo explica que hace falta volver a entrar", async () => {
    http.cuando("POST", RESET, {
      status: 403,
      body: error("stale_mfa", "para reiniciar el MFA hace falta un MFA reciente"),
    });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.type(screen.getByLabelText("Motivo"), "dispositivo perdido");
    await usuario.type(screen.getByLabelText('Escribe "RESET" para confirmar'), "reset");
    await usuario.click(
      screen.getByRole("button", { name: /Reiniciar el segundo factor/ }),
    );

    expect(await screen.findByText("Hace falta un MFA reciente")).toBeVisible();
    expect(screen.getByText(/Cierra la sesión, vuelve a entrar/)).toBeVisible();
  });

  it("un 401 se comunica al proveedor para volver al acceso", async () => {
    const aviso = vi.fn();
    http.cuando("GET", USUARIO, {
      status: 401,
      body: error("session_expired", "sesion inexistente o caducada"),
    });
    const { usuario } = montarConSesion(<TotpAdminPage />, {
      reportAuthFailure: aviso,
    });

    await escribirObjetivo(usuario);
    await usuario.click(screen.getByRole("button", { name: /Consultar estado/ }));

    await screen.findByText("La sesión ya no es válida");
    expect(aviso).toHaveBeenCalledTimes(1);
  });

  it("cambiar de objetivo descarta el estado y el QR anteriores", async () => {
    http.cuando("GET", USUARIO, { status: 200, body: EMPLEADO });
    const { usuario } = conObjetivo();

    await escribirObjetivo(usuario);
    await usuario.click(screen.getByRole("button", { name: /Consultar estado/ }));
    await screen.findByText("eva.employee");

    await usuario.type(screen.getByLabelText("UUID del empleado"), "0");

    expect(screen.queryByText("eva.employee")).toBeNull();
    expect(screen.queryByTitle(/Inscripción TOTP/)).toBeNull();
  });
});
