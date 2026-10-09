import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  desafio,
  error,
  instalarHttpDoble,
  PREFIJO,
  URI_OTPAUTH,
  type HttpDoble,
} from "../../test/httpDouble";
import { montarApp } from "../../test/render";

const LOGIN = `${PREFIJO}/auth/login`;
const INSCRIPCION = `${PREFIJO}/auth/enrollment/totp`;

const AVISO_PENDIENTE =
  /Tu autenticación TOTP está pendiente de confirmación\. Si aún no la configuraste, abre Google Authenticator/;

async function accederCon(
  http: HttpDoble,
  cuerpo: Record<string, unknown>,
): Promise<ReturnType<typeof montarApp>> {
  http.cuando("POST", LOGIN, { status: 200, body: desafio(cuerpo) });
  const vista = montarApp("/login");
  await vista.usuario.type(screen.getByLabelText("Usuario"), "ada.admin");
  await vista.usuario.type(screen.getByLabelText("Contraseña"), "contrasena-de-prueba");
  await vista.usuario.click(
    screen.getByRole("button", { name: /Continuar al segundo factor/ }),
  );
  await screen.findByRole("heading", { name: "Segundo factor" });
  return vista;
}

describe("aviso del estado del segundo factor", () => {
  let http: HttpDoble;

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("pending muestra el aviso completo, valido tambien para quien ya lo configuro", async () => {
    await accederCon(http, { totp_status: "pending", enrollment_id: "aut-1" });

    expect(screen.getByText(AVISO_PENDIENTE)).toBeVisible();
    // El aviso contempla las dos situaciones: con autenticador y sin el.
    expect(
      screen.getByText(/Si ya la configuraste, introduce el código de seis dígitos/),
    ).toBeVisible();
    // Y el campo del codigo sigue ahi: pending no bloquea el acceso.
    expect(screen.getByLabelText("Código de seis dígitos")).toBeVisible();
  });

  it("reset_required avisa de una semilla nueva sin confirmar", async () => {
    await accederCon(http, { totp_status: "reset_required", enrollment_id: "aut-2" });

    expect(
      screen.getByText(/existe una semilla\s+nueva pendiente de confirmación/),
    ).toBeVisible();
  });

  it("disabled no deja continuar como si el MFA estuviera activo", async () => {
    await accederCon(http, { totp_status: "disabled", enrollment_id: null });

    expect(screen.getByText("Segundo factor deshabilitado")).toBeVisible();
    expect(screen.queryByRole("button", { name: /código QR de inscripción/ })).toBeNull();
  });

  it("confirmed no muestra ningun aviso de pendiente", async () => {
    await accederCon(http, { totp_status: "confirmed", enrollment_id: null });

    expect(screen.queryByText(AVISO_PENDIENTE)).toBeNull();
  });

  it("sin estado en el desafio da la instruccion general y declara el limite", async () => {
    await accederCon(http, {});

    expect(
      screen.getByText(/no ha informado el estado de tu inscripción/),
    ).toBeVisible();
    expect(screen.queryByText(AVISO_PENDIENTE)).toBeNull();
  });
});

describe("inscripcion inicial del propio TOTP", () => {
  let http: HttpDoble;

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("no pide nada hasta que se pulsa, y entrega el QR del URI real", async () => {
    const { usuario } = await accederCon(http, {
      totp_status: "pending",
      enrollment_id: "aut-1",
    });
    http.cuando("POST", INSCRIPCION, {
      status: 200,
      body: {
        username: "ada.admin",
        totp_status: "pending",
        totp_enrollment_uri: URI_OTPAUTH,
        warning: "Este URI se entrega UNA sola vez.",
      },
    });
    expect(http.contar("POST", INSCRIPCION)).toBe(0);

    await usuario.click(
      screen.getByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    );

    expect(await screen.findByTitle("Inscripción TOTP de ada.admin")).toBeInTheDocument();
    expect(screen.getByText(/Escanear código QR/)).toBeVisible();
    // Se conservan los parametros del URI tal como los genero Vault.
    expect(screen.getByText(/6\s+dígitos · 30 s · SHA1/)).toBeVisible();
    expect(http.ultima("POST", INSCRIPCION)?.body).toEqual({
      enrollment_id: "aut-1",
    });
    expect(http.contar("POST", INSCRIPCION)).toBe(1);
  });

  it("la autorizacion es de un solo uso: no queda boton para repetirla", async () => {
    const { usuario } = await accederCon(http, {
      totp_status: "pending",
      enrollment_id: "aut-1",
    });
    http.cuando("POST", INSCRIPCION, {
      status: 200,
      body: {
        username: "ada.admin",
        totp_status: "pending",
        totp_enrollment_uri: URI_OTPAUTH,
        warning: "una sola vez",
      },
    });

    await usuario.click(
      screen.getByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    );
    await screen.findByTitle("Inscripción TOTP de ada.admin");
    await usuario.click(
      screen.getByRole("button", { name: /Ya lo escaneé: ocultar el código/ }),
    );

    expect(
      screen.queryByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    ).toBeNull();
    expect(screen.getByText(/El QR de inscripción no está disponible/)).toBeVisible();
    expect(http.contar("POST", INSCRIPCION)).toBe(1);
  });

  it("un 409 explica el reset administrativo y no vuelve a pedir semilla", async () => {
    const { usuario } = await accederCon(http, {
      totp_status: "pending",
      enrollment_id: "aut-1",
    });
    http.cuando("POST", INSCRIPCION, {
      status: 409,
      body: error(
        "totp_already_enrolled",
        "esta identidad ya tiene una semilla TOTP registrada en Vault",
      ),
    });

    await usuario.click(
      screen.getByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    );

    expect(
      await screen.findByText("Ya existe una inscripción para esta identidad"),
    ).toBeVisible();
    expect(screen.getByText(/El QR de inscripción no está disponible/)).toBeVisible();
    expect(screen.getByText(/reset administrativo\s+explícito/)).toBeVisible();
    // Y se sigue pudiendo introducir el codigo si ya tenia la cuenta.
    expect(screen.getByLabelText("Código de seis dígitos")).toBeVisible();
    expect(http.contar("POST", INSCRIPCION)).toBe(1);
  });

  it("pending sin autorizacion dice que no hay QR y a quien pedirlo", async () => {
    await accederCon(http, { totp_status: "pending", enrollment_id: null });

    expect(screen.getByText(AVISO_PENDIENTE)).toBeVisible();
    expect(screen.getByText(/El QR de inscripción no está disponible/)).toBeVisible();
    expect(
      screen.queryByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    ).toBeNull();
  });

  it("no dibuja un QR si lo recibido no es un URI otpauth", async () => {
    const { usuario } = await accederCon(http, {
      totp_status: "pending",
      enrollment_id: "aut-1",
    });
    http.cuando("POST", INSCRIPCION, {
      status: 200,
      body: {
        username: "ada.admin",
        totp_status: "pending",
        // Ni el challenge_id, ni el username, ni una URL del sitio sirven.
        totp_enrollment_uri: "https://example.invalid/qr?challenge=desafio-0001",
        warning: "una sola vez",
      },
    });

    await usuario.click(
      screen.getByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    );

    expect(
      await screen.findByText("La inscripción recibida no es utilizable"),
    ).toBeVisible();
    expect(screen.queryByTitle(/Inscripción TOTP/)).toBeNull();
  });

  it("volver al acceso descarta el QR en pantalla", async () => {
    const { usuario } = await accederCon(http, {
      totp_status: "pending",
      enrollment_id: "aut-1",
    });
    http.cuando("POST", INSCRIPCION, {
      status: 200,
      body: {
        username: "ada.admin",
        totp_status: "pending",
        totp_enrollment_uri: URI_OTPAUTH,
        warning: "una sola vez",
      },
    });

    await usuario.click(
      screen.getByRole("button", { name: /Mostrar mi código QR de inscripción/ }),
    );
    await screen.findByTitle("Inscripción TOTP de ada.admin");
    await usuario.click(
      screen.getByRole("button", { name: /Volver al inicio de sesión/ }),
    );

    expect(screen.queryByTitle(/Inscripción TOTP/)).toBeNull();
    expect(screen.getByRole("heading", { name: "Iniciar sesión" })).toBeVisible();
  });
});
