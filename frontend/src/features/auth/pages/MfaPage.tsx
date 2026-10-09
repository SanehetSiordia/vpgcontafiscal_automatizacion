import { useEffect, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";

import { ROUTES } from "../../../shared/config/env";
import { Alert } from "../../../shared/ui/Alert";
import { Button } from "../../../shared/ui/Button";
import { CodeField } from "../../../shared/ui/CodeField";
import { PendingNotice } from "../../totp/PendingNotice";
import { SelfEnrollmentPanel } from "../../totp/SelfEnrollmentPanel";
import { useAuth } from "../state/AuthContext";

/**
 * Paso 2: el código TOTP.
 *
 * Sobre el tiempo restante: el contrato expone `expires_in_seconds`, un plazo
 * **relativo**, y no publica la hora del servidor. Así que la cuenta atrás se
 * lleva en este navegador y se presenta como aproximada; inventar una precisión
 * que el contrato no da sería peor que no mostrarla.
 *
 * El código no se genera aquí ni se valida aquí, y no se envía dígito a dígito:
 * un solo envío explícito, con el botón bloqueado mientras está en curso.
 */
export function MfaPage() {
  const { state, submitCode, backToLogin } = useAuth();
  const [codigo, setCodigo] = useState("");
  const [errorLocal, setErrorLocal] = useState<string | null>(null);
  const [restante, setRestante] = useState(
    state.challenge?.expires_in_seconds ?? 0,
  );

  const verificando = state.status === "verifying_mfa";

  useEffect(() => {
    if (restante <= 0) return;
    const tic = window.setInterval(() => {
      setRestante((valor) => (valor <= 1 ? 0 : valor - 1));
    }, 1000);
    return () => window.clearInterval(tic);
  }, [restante]);

  if (state.status === "authenticated") {
    return <Navigate to={ROUTES.inicio} replace />;
  }
  if (state.challenge === null) {
    // Recargar la página pierde el desafío, porque vive en memoria. No se
    // intenta recuperarlo: se vuelve al primer paso.
    return <Navigate to={ROUTES.login} replace />;
  }

  const challenge = state.challenge;

  const enviar = (evento: FormEvent<HTMLFormElement>): void => {
    evento.preventDefault();
    if (codigo.length !== 6) {
      setErrorLocal("El código tiene exactamente seis dígitos.");
      return;
    }
    setErrorLocal(null);
    void submitCode(codigo).then(() => setCodigo(""));
  };

  return (
    <section className="vpg-tarjeta" aria-labelledby="titulo-mfa">
      <h2 className="vpg-tarjeta__titulo" id="titulo-mfa">
        Segundo factor
      </h2>
      <p className="vpg-tarjeta__intro">
        Tu contraseña es correcta, pero <strong>todavía no hay sesión</strong>:
        se abre al validar el código contra Vault. Método configurado:{" "}
        <code className="vpg-codigo-en-linea">{challenge.method_name}</code>.
      </p>

      <PendingNotice status={challenge.totp_status ?? null} />

      {state.error !== null ? (
        <Alert
          tone="error"
          title={
            state.error.status === 429
              ? "Demasiados intentos"
              : "El código no se pudo validar"
          }
          requestId={state.error.requestId}
          fields={state.error.fields}
        >
          <p>{state.error.message}</p>
          {state.error.status === 429 && state.error.retryAfterSeconds ? (
            <p>
              Espera {state.error.retryAfterSeconds} s. No se reenvía ningún
              código de forma automática.
            </p>
          ) : null}
        </Alert>
      ) : null}

      <form onSubmit={enviar} noValidate>
        <CodeField
          value={codigo}
          onChange={(valor) => {
            setCodigo(valor);
            if (errorLocal) setErrorLocal(null);
          }}
          disabled={verificando}
          error={errorLocal}
        />
        <Button type="submit" busy={verificando} busyLabel="Validando...">
          Validar y entrar
        </Button>
      </form>

      <p className="vpg-campo__ayuda" aria-live="polite">
        {restante > 0
          ? `El desafío caduca en unos ${restante} s (plazo aproximado, contado en este navegador).`
          : "El plazo del desafío ha pasado: si falla, repite el acceso."}
      </p>

      <div className="vpg-acciones">
        <Button variante="sutil" onClick={backToLogin}>
          Volver al inicio de sesión
        </Button>
      </div>

      <SelfEnrollmentPanel />
    </section>
  );
}
