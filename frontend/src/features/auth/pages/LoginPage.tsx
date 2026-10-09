import { useEffect, useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { ROUTES } from "../../../shared/config/env";
import { Alert } from "../../../shared/ui/Alert";
import { Button } from "../../../shared/ui/Button";
import { PasswordField, TextField } from "../../../shared/ui/TextField";
import { useAuth } from "../state/AuthContext";

/** El mismo patrón que valida `USERNAME_RE` en el backend. */
const USERNAME_RE = /^[a-z0-9._-]{3,64}$/;

/**
 * Paso 1: usuario y contraseña.
 *
 * Lo que esta pantalla **no** hace, y es deliberado:
 *
 *  * no declara a nadie autenticado al validar la contraseña: un desafío no es
 *    una sesión, y la navegación a `/mfa` la decide el estado, no la respuesta;
 *  * no conserva la contraseña: vive en el estado del formulario y se borra en
 *    cuanto el envío sale bien;
 *  * no reenvía nada solo: ni tras un 429, ni tras un 503, ni tras un error de
 *    red. Siempre hace falta otro clic.
 */
export function LoginPage() {
  const { state, signIn, clearFeedback } = useAuth();
  const location = useLocation();
  // Lo pone ProtectedRoute al rechazar una ruta sin sesion (p. ej. tras una
  // recarga, que la pierde porque vive solo en memoria).
  const sesionRequerida =
    typeof location.state === "object" &&
    location.state !== null &&
    (location.state as Record<string, unknown>)["sesionRequerida"] === true;
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errorUsuario, setErrorUsuario] = useState<string | null>(null);
  const [errorPassword, setErrorPassword] = useState<string | null>(null);
  const [esperaSegundos, setEsperaSegundos] = useState(0);

  const error = state.error;
  const enviando = state.status === "logging_in";
  // 403 por token emitido sin MFA: es un fallo de configuración del
  // enforcement, no una credencial mala. Se bloquea el acceso y se explica.
  const mfaSinExigir = error?.code === "mfa_not_enforced";

  useEffect(() => {
    const espera = error?.retryAfterSeconds ?? 0;
    if (espera > 0) setEsperaSegundos(espera);
  }, [error]);

  useEffect(() => {
    if (esperaSegundos <= 0) return;
    const tic = window.setInterval(() => {
      setEsperaSegundos((valor) => (valor <= 1 ? 0 : valor - 1));
    }, 1000);
    return () => window.clearInterval(tic);
  }, [esperaSegundos]);

  if (state.status === "mfa_required" || state.status === "verifying_mfa") {
    return <Navigate to={ROUTES.mfa} replace />;
  }
  if (state.status === "authenticated") {
    return <Navigate to={ROUTES.inicio} replace />;
  }

  const enviar = (evento: FormEvent<HTMLFormElement>): void => {
    evento.preventDefault();
    const usuario = username.trim().toLowerCase();
    const faltaUsuario = !USERNAME_RE.test(usuario)
      ? "Entre 3 y 64 caracteres: letras minúsculas, dígitos, punto, guion o guion bajo."
      : null;
    const faltaPassword = password.length === 0 ? "Escribe tu contraseña." : null;

    setErrorUsuario(faltaUsuario);
    setErrorPassword(faltaPassword);
    if (faltaUsuario !== null || faltaPassword !== null) return;
    if (esperaSegundos > 0 || mfaSinExigir) return;

    void signIn(usuario, password).then(() => {
      // Se descarta la contraseña en cuanto deja de hacer falta. Si el login
      // falló, también: se vuelve a escribir.
      setPassword("");
    });
  };

  return (
    <section className="vpg-tarjeta" aria-labelledby="titulo-login">
      <h2 className="vpg-tarjeta__titulo" id="titulo-login">
        Iniciar sesión
      </h2>
      <p className="vpg-tarjeta__intro">
        El acceso tiene dos pasos. Este es el primero: comprobar tu contraseña.
        Después hará falta el código de seis dígitos de tu autenticador.
      </p>

      {state.notice ? <Alert tone="info">{state.notice}</Alert> : null}

      {sesionRequerida && state.notice === null ? (
        <Alert tone="info" title="Hace falta iniciar sesión">
          <p>
            Esa pantalla necesita una sesión activa. Las sesiones viven solo en
            memoria, así que recargar la página o reiniciar el servicio obliga a
            entrar otra vez.
          </p>
        </Alert>
      ) : null}

      {mfaSinExigir ? (
        <Alert
          tone="error"
          title="Configuración incorrecta: el segundo factor no se está exigiendo"
          requestId={error?.requestId}
        >
          <p>{error?.message}</p>
          <p>
            El acceso queda bloqueado a propósito. Vault entregó un token solo
            con la contraseña, lo que significa que el <em>enforcement</em> de
            MFA no cubre el montaje <code className="vpg-codigo-en-linea">userpass</code>.
            Ese token no se usa como sesión. Avisa a quien administre Vault
            antes de volver a intentarlo.
          </p>
        </Alert>
      ) : null}

      {error !== null && !mfaSinExigir ? (
        <Alert
          tone="error"
          title={tituloDeError(error.status, error.code)}
          requestId={error.requestId}
          fields={error.fields}
        >
          <p>{error.message}</p>
          {error.status === 429 ? (
            <p>
              Espera {esperaSegundos > 0 ? `${esperaSegundos} s` : "un momento"} y
              vuelve a intentarlo. No se reenvía nada de forma automática.
            </p>
          ) : null}
          {error.status === 503 || error.status === 0 ? (
            <p>
              Es un estado temporal del backend, no significa que tu cuenta no
              exista. No se crea ninguna cuenta ni ningún QR por esto.
            </p>
          ) : null}
        </Alert>
      ) : null}

      <form onSubmit={enviar} noValidate>
        <TextField
          label="Usuario"
          name="username"
          value={username}
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          inputMode="text"
          maxLength={64}
          required
          disabled={enviando || mfaSinExigir}
          error={errorUsuario}
          help="El mismo nombre que usas en Vault. Se normaliza a minúsculas."
          onChange={(evento) => {
            setUsername(evento.target.value);
            if (errorUsuario) setErrorUsuario(null);
            if (error) clearFeedback();
          }}
        />
        <PasswordField
          label="Contraseña"
          name="password"
          value={password}
          autoComplete="current-password"
          required
          disabled={enviando || mfaSinExigir}
          error={errorPassword}
          onChange={(evento) => {
            setPassword(evento.target.value);
            if (errorPassword) setErrorPassword(null);
            if (error) clearFeedback();
          }}
        />
        <Button
          type="submit"
          busy={enviando}
          busyLabel="Comprobando..."
          disabled={mfaSinExigir || esperaSegundos > 0}
        >
          Continuar al segundo factor
        </Button>
      </form>

      <p className="vpg-campo__ayuda">
        Esta pantalla no crea cuentas ni restablece contraseñas. Si tu
        autenticador todavía no tiene la cuenta, el paso siguiente te lo dirá.
      </p>
    </section>
  );
}

function tituloDeError(status: number, code: string): string {
  if (status === 401) return "Usuario o contraseña incorrectos";
  if (status === 403 && code === "not_provisioned") {
    return "Tu identidad no está registrada como empleado";
  }
  if (status === 403) return "No puedes acceder con esta cuenta";
  if (status === 422) return "Revisa los datos del formulario";
  if (status === 429) return "Demasiados intentos";
  if (status === 503) return "El servicio no está disponible todavía";
  if (status === 0) return "No se pudo contactar con el servicio";
  return "No se pudo iniciar sesión";
}
