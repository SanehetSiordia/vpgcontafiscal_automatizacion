import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  desafio,
  error,
  instalarHttpDoble,
  instalarRedCaida,
  PREFIJO,
  principal,
  sesion,
  type HttpDoble,
} from "../../../test/httpDouble";
import { montarApp } from "../../../test/render";

const LOGIN = `${PREFIJO}/auth/login`;
const VERIFY = `${PREFIJO}/auth/mfa/verify`;
const ME = `${PREFIJO}/auth/me`;
const LOGOUT = `${PREFIJO}/auth/logout`;

async function llegarAlSegundoFactor(
  http: HttpDoble,
  extraDesafio: Record<string, unknown> = {},
): Promise<ReturnType<typeof montarApp>> {
  http.cuando("POST", LOGIN, {
    status: 200,
    body: desafio({ totp_status: "confirmed", enrollment_id: null, ...extraDesafio }),
  });
  const vista = montarApp("/login");
  await vista.usuario.type(screen.getByLabelText("Usuario"), "ada.admin");
  await vista.usuario.type(screen.getByLabelText("Contraseña"), "contrasena-de-prueba");
  await vista.usuario.click(
    screen.getByRole("button", { name: /Continuar al segundo factor/ }),
  );
  await screen.findByRole("heading", { name: "Segundo factor" });
  return vista;
}

describe("segundo factor", () => {
  let http: HttpDoble;

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("un codigo valido abre sesion y consulta el principal al backend", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, { status: 200, body: sesion() });
    http.cuando("GET", ME, { status: 200, body: principal() });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123456");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    expect(await screen.findByText(/Bienvenido, ada.admin/)).toBeVisible();
    expect(http.ultima("GET", ME)?.headers["Authorization"]).toBe(
      "Bearer sesion-opaca-de-prueba",
    );
    expect(http.contar("POST", VERIFY)).toBe(1);
    expect(http.contar("GET", ME)).toBe(1);
  });

  it("conserva los ceros iniciales del codigo", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, { status: 200, body: sesion() });
    http.cuando("GET", ME, { status: 200, body: principal() });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "012345");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    await screen.findByText(/Bienvenido/);
    expect(http.ultima("POST", VERIFY)?.body).toMatchObject({ code: "012345" });
  });

  it("acepta un codigo pegado con espacios", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    const campo = screen.getByLabelText("Código de seis dígitos");

    await usuario.click(campo);
    await usuario.paste("123 456");

    expect(campo).toHaveValue("123456");
  });

  it("no envia nada hasta que se pulsa el boton", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123456");

    expect(http.contar("POST", VERIFY)).toBe(0);
  });

  it("rechaza un codigo incompleto sin llamar al servicio", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    expect(
      await screen.findByText(/El código tiene exactamente seis dígitos/),
    ).toBeVisible();
    expect(http.contar("POST", VERIFY)).toBe(0);
  });

  it("un codigo incorrecto deja reintentar y no abre sesion", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, {
      status: 401,
      body: error("mfa_failed", "codigo TOTP incorrecto"),
    });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "000000");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    expect(await screen.findByText(/codigo TOTP incorrecto/)).toBeVisible();
    expect(screen.getByRole("heading", { name: "Segundo factor" })).toBeVisible();
    expect(http.contar("GET", ME)).toBe(0);
  });

  it("un desafio caducado vuelve al acceso con su aviso", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, {
      status: 401,
      body: error("challenge_expired", "el desafio MFA no existe o ha caducado"),
    });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123456");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    expect(
      await screen.findByRole("heading", { name: "Iniciar sesión" }),
    ).toBeVisible();
    expect(screen.getByText(/ha caducado o se ha consumido/)).toBeVisible();
  });

  it("un 429 en el segundo factor no reenvia el codigo solo", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, {
      status: 429,
      headers: { "Retry-After": "15" },
      body: error("rate_limited", "has superado el limite"),
    });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123456");
    await usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));

    expect(await screen.findByText("Demasiados intentos")).toBeVisible();
    await waitFor(() => expect(http.contar("POST", VERIFY)).toBe(1));
  });

  it("un doble clic no gasta dos veces el desafio", async () => {
    const { usuario } = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, { status: 200, body: sesion() });
    http.cuando("GET", ME, { status: 200, body: principal() });
    const boton = screen.getByRole("button", { name: /Validar y entrar/ });

    await usuario.type(screen.getByLabelText("Código de seis dígitos"), "123456");
    await usuario.dblClick(boton);

    await screen.findByText(/Bienvenido/);
    expect(http.contar("POST", VERIFY)).toBe(1);
  });

  it("entrar directamente en /mfa sin desafio vuelve al acceso", async () => {
    montarApp("/mfa");

    expect(
      await screen.findByRole("heading", { name: "Iniciar sesión" }),
    ).toBeVisible();
    expect(http.llamadas).toHaveLength(0);
  });

  it("el plazo se presenta como aproximado, no como hora del servidor", async () => {
    await llegarAlSegundoFactor(http);

    expect(
      screen.getByText(/plazo aproximado, contado en este navegador/),
    ).toBeVisible();
  });
});

describe("cierre de sesion", () => {
  let http: HttpDoble;

  async function entrar(): Promise<ReturnType<typeof montarApp>> {
    const vista = await llegarAlSegundoFactor(http);
    http.cuando("POST", VERIFY, { status: 200, body: sesion() });
    http.cuando("GET", ME, { status: 200, body: principal() });
    await vista.usuario.type(
      screen.getByLabelText("Código de seis dígitos"),
      "123456",
    );
    await vista.usuario.click(screen.getByRole("button", { name: /Validar y entrar/ }));
    await screen.findByText(/Bienvenido/);
    return vista;
  }

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("un 204 confirma la revocacion y vuelve al acceso", async () => {
    const { usuario } = await entrar();
    http.cuando("POST", LOGOUT, { status: 204 });

    await usuario.click(screen.getByRole("button", { name: /Cerrar sesión/ }));

    expect(await screen.findByText(/revocó su token de Vault/)).toBeVisible();
    expect(screen.getByRole("heading", { name: "Iniciar sesión" })).toBeVisible();
  });

  it("un 401 se trata como sesion ya cerrada, sin parsear cuerpo", async () => {
    const { usuario } = await entrar();
    http.cuando("POST", LOGOUT, { status: 401 });

    await usuario.click(screen.getByRole("button", { name: /Cerrar sesión/ }));

    expect(await screen.findByText(/ya no existía en el servidor/)).toBeVisible();
  });

  it("si falla la red no afirma que el servidor haya revocado nada", async () => {
    const { usuario } = await entrar();
    instalarRedCaida();

    await usuario.click(screen.getByRole("button", { name: /Cerrar sesión/ }));

    const aviso = await screen.findByText(/no se ha podido confirmar la revocación/);
    expect(aviso).toBeVisible();
    expect(screen.getByRole("heading", { name: "Iniciar sesión" })).toBeVisible();
  });
});
