import { screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  desafio,
  error,
  instalarHttpDoble,
  instalarRedCaida,
  PREFIJO,
  type HttpDoble,
} from "../../../test/httpDouble";
import { montarApp } from "../../../test/render";

const LOGIN = `${PREFIJO}/auth/login`;

async function enviarCredenciales(
  usuario: ReturnType<typeof montarApp>["usuario"],
  nombre = "ada.admin",
  password = "contrasena-de-prueba",
): Promise<void> {
  await usuario.type(screen.getByLabelText("Usuario"), nombre);
  await usuario.type(screen.getByLabelText("Contraseña"), password);
  await usuario.click(
    screen.getByRole("button", { name: /Continuar al segundo factor/ }),
  );
}

describe("pantalla de acceso", () => {
  let http: HttpDoble;

  beforeEach(() => {
    http = instalarHttpDoble();
  });

  it("empieza sin sesion y sin pedir nada al servicio", () => {
    montarApp("/login");

    expect(screen.getByRole("heading", { name: "Iniciar sesión" })).toBeVisible();
    // Montar la pantalla no dispara ninguna peticion, ni con StrictMode.
    expect(http.llamadas).toHaveLength(0);
  });

  it("valida en el cliente antes de molestar al servicio", async () => {
    const { usuario } = montarApp("/login");

    await usuario.click(
      screen.getByRole("button", { name: /Continuar al segundo factor/ }),
    );

    expect(await screen.findByText(/Escribe tu contraseña/)).toBeVisible();
    expect(http.llamadas).toHaveLength(0);
  });

  it("un desafio valido lleva al segundo factor y NO declara sesion", async () => {
    http.cuando("POST", LOGIN, {
      status: 200,
      body: desafio({ totp_status: "confirmed", enrollment_id: null }),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(await screen.findByRole("heading", { name: "Segundo factor" })).toBeVisible();
    expect(screen.getByText(/todavía no hay sesión/)).toBeVisible();
    expect(http.contar("POST", LOGIN)).toBe(1);
  });

  it("descarta la contrasena del formulario al enviarla", async () => {
    http.cuando("POST", LOGIN, { status: 200, body: desafio() });
    const { usuario } = montarApp("/login");
    const campo = screen.getByLabelText("Contraseña") as HTMLInputElement;

    await enviarCredenciales(usuario);
    await screen.findByRole("heading", { name: "Segundo factor" });

    expect(campo).not.toBeInTheDocument();
  });

  it("muestra el usuario o contrasena incorrectos del 401", async () => {
    http.cuando("POST", LOGIN, {
      status: 401,
      body: error("unauthenticated", "usuario o contrasena incorrectos"),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario, "ada.admin", "la-que-no-es");

    expect(
      await screen.findByText("Usuario o contraseña incorrectos"),
    ).toBeVisible();
  });

  it("un 403 por token sin MFA bloquea el acceso y se explica como configuracion", async () => {
    http.cuando("POST", LOGIN, {
      status: 403,
      body: error(
        "mfa_not_enforced",
        "el enforcement MFA no esta cubriendo el montaje userpass",
      ),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(
      await screen.findByText(/el segundo factor no se está exigiendo/),
    ).toBeVisible();
    // Ni se entra, ni se interpreta ese token como sesion, ni se deja reenviar.
    expect(
      screen.getByRole("button", { name: /Continuar al segundo factor/ }),
    ).toBeDisabled();
    expect(screen.queryByRole("heading", { name: "Segundo factor" })).toBeNull();
  });

  it("un 403 de empleado no registrado se distingue de una contrasena mala", async () => {
    http.cuando("POST", LOGIN, {
      status: 403,
      body: error(
        "not_provisioned",
        "este usuario no esta registrado como empleado en PostgreSQL",
      ),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(
      await screen.findByText("Tu identidad no está registrada como empleado"),
    ).toBeVisible();
  });

  it("un 422 lista campo y motivo, sin el valor enviado", async () => {
    http.cuando("POST", LOGIN, {
      status: 422,
      body: error("validation_error", "el cuerpo no supera la validacion", {
        fields: [{ field: "username", reason: "username invalido" }],
      }),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario, "ada.admin", "mi-secreto-visible");

    expect(await screen.findByText(/username invalido/)).toBeVisible();
    expect(screen.queryByText(/mi-secreto-visible/)).toBeNull();
  });

  it("un 429 respeta Retry-After, lo muestra y no reenvia solo", async () => {
    http.cuando("POST", LOGIN, {
      status: 429,
      headers: { "Retry-After": "30" },
      body: error("rate_limited", "has superado el limite de peticiones"),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(await screen.findByText("Demasiados intentos")).toBeVisible();
    expect(screen.getByText(/Espera 30 s/)).toBeVisible();
    expect(
      screen.getByRole("button", { name: /Continuar al segundo factor/ }),
    ).toBeDisabled();
    await waitFor(() => expect(http.contar("POST", LOGIN)).toBe(1));
  });

  it("un 503 se presenta como estado temporal, no como cuenta inexistente", async () => {
    http.cuando("POST", LOGIN, {
      status: 503,
      body: error("upstream_unavailable", "Vault esta sellado: desbloquealo"),
    });
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(
      await screen.findByText("El servicio no está disponible todavía"),
    ).toBeVisible();
    expect(screen.getByText(/no significa que tu cuenta no/)).toBeVisible();
  });

  it("si la red no responde lo dice sin inventar un codigo de la API", async () => {
    instalarRedCaida();
    const { usuario } = montarApp("/login");

    await enviarCredenciales(usuario);

    expect(
      await screen.findByText("No se pudo contactar con el servicio"),
    ).toBeVisible();
  });

  it("una ruta protegida sin sesion vuelve al acceso y lo explica", async () => {
    montarApp("/inicio");

    expect(
      await screen.findByText("Hace falta iniciar sesión"),
    ).toBeVisible();
    expect(http.llamadas).toHaveLength(0);
  });

  it("una ruta de interfaz desconocida no pide nada y vuelve al acceso", async () => {
    montarApp("/ruta/que/no/existe");

    expect(
      await screen.findByRole("heading", { name: "Iniciar sesión" }),
    ).toBeVisible();
    expect(http.llamadas).toHaveLength(0);
  });
});
