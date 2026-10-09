import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { ROUTES } from "../../../shared/config/env";
import { Alert } from "../../../shared/ui/Alert";
import { Button } from "../../../shared/ui/Button";
import { PasswordField, TextField } from "../../../shared/ui/TextField";
import { useAuth } from "../../auth/state/AuthContext";
import { toAuthError, type AuthError } from "../../auth/state/reducer";
import * as api from "../api";
import { EnrollmentQr } from "../EnrollmentQr";
import { UUID_RE, type EnrollmentOut, type UserDetail } from "../types";

type Tarea = "consulta" | "provision" | "reset" | null;

/**
 * Herramienta mínima de inscripción TOTP, solo para `admin`.
 *
 * Es deliberadamente pequeña: recibe el **UUID** del empleado objetivo, consulta
 * lo imprescindible con el GET real y ejecuta el aprovisionamiento o el reset
 * con sus DTO reales. No hay alta de empleados ni búsqueda por nombre: esos
 * endpoints no son parte de esta etapa, y una caja de búsqueda inventada
 * llamaría a rutas que no existen.
 *
 * Nada se dispara al abrir la pantalla, ni al recibir `pending`, ni al navegar:
 * las tres operaciones salen de un envío explícito, y el reset exige además
 * escribir la palabra de confirmación que pide el contrato.
 */
export function TotpAdminPage() {
  const { state, reportAuthFailure } = useAuth();
  const session = state.session;

  const [uuid, setUuid] = useState("");
  const [errorUuid, setErrorUuid] = useState<string | null>(null);
  const [usuario, setUsuario] = useState<UserDetail | null>(null);
  const [inscripcion, setInscripcion] = useState<EnrollmentOut | null>(null);
  const [error, setError] = useState<AuthError | null>(null);
  const [tarea, setTarea] = useState<Tarea>(null);

  const [passwordInicial, setPasswordInicial] = useState("");
  const [usuarioVault, setUsuarioVault] = useState("");
  const [motivo, setMotivo] = useState("");
  const [confirmacion, setConfirmacion] = useState("");

  const enCurso = useRef(false);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  // Cambiar de objetivo descarta lo anterior: el URI de otra persona no debe
  // seguir en pantalla ni un segundo.
  useEffect(() => {
    setUsuario(null);
    setInscripcion(null);
    setError(null);
  }, [uuid]);

  if (session === null) return null;

  const ejecutar = async (
    cual: Exclude<Tarea, null>,
    operacion: (signal: AbortSignal) => Promise<void>,
  ): Promise<void> => {
    if (enCurso.current) return;
    enCurso.current = true;
    setTarea(cual);
    setError(null);
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    try {
      await operacion(controller.signal);
    } catch (fallo) {
      // Un 401 aquí significa que la sesión murió: se devuelve al login en vez
      // de dejar la pantalla a medias.
      reportAuthFailure(fallo);
      setError(toAuthError(fallo));
    } finally {
      setTarea(null);
      enCurso.current = false;
    }
  };

  const objetivoValido = (): boolean => {
    const valor = uuid.trim();
    if (!UUID_RE.test(valor)) {
      setErrorUuid("Escribe el UUID del empleado, con sus guiones.");
      return false;
    }
    setErrorUuid(null);
    return true;
  };

  const consultar = (evento: FormEvent<HTMLFormElement>): void => {
    evento.preventDefault();
    if (!objetivoValido()) return;
    void ejecutar("consulta", async (signal) => {
      setUsuario(await api.getUser(session, uuid.trim(), signal));
    });
  };

  const aprovisionar = (evento: FormEvent<HTMLFormElement>): void => {
    evento.preventDefault();
    if (!objetivoValido() || passwordInicial.length === 0) return;
    void ejecutar("provision", async (signal) => {
      const resultado = await api.provisionVault(
        session,
        uuid.trim(),
        {
          initial_password: passwordInicial,
          ...(usuarioVault.trim() ? { vault_username: usuarioVault.trim() } : {}),
        },
        signal,
      );
      setPasswordInicial("");
      setInscripcion(resultado);
      setUsuario(await api.getUser(session, uuid.trim(), signal));
    });
  };

  const reiniciar = (evento: FormEvent<HTMLFormElement>): void => {
    evento.preventDefault();
    if (!objetivoValido() || confirmacion !== "RESET" || motivo.trim().length < 3) {
      return;
    }
    void ejecutar("reset", async (signal) => {
      const resultado = await api.resetMfa(
        session,
        uuid.trim(),
        { confirm: "RESET", reason: motivo.trim() },
        signal,
      );
      setConfirmacion("");
      setMotivo("");
      setInscripcion(resultado);
      setUsuario(await api.getUser(session, uuid.trim(), signal));
    });
  };

  return (
    <>
      <section className="vpg-tarjeta" aria-labelledby="titulo-totp">
        <h2 className="vpg-tarjeta__titulo" id="titulo-totp">
          Inscripción TOTP de un empleado
        </h2>
        <p className="vpg-tarjeta__intro">
          Entrega el QR de inscripción a su titular en persona. El URI se muestra{" "}
          <strong>una sola vez</strong> y no se puede volver a pedir: ningún GET
          lo devuelve.
        </p>

        <form onSubmit={consultar} noValidate>
          <TextField
            label="UUID del empleado"
            value={uuid}
            placeholder="00000000-0000-4000-8000-000000000000"
            autoComplete="off"
            spellCheck={false}
            error={errorUuid}
            help="Esta etapa no implementa búsqueda de empleados: el identificador se obtiene del CRUD o de la base."
            onChange={(evento) => setUuid(evento.target.value)}
          />
          <Button
            type="submit"
            variante="secundario"
            busy={tarea === "consulta"}
            busyLabel="Consultando..."
          >
            Consultar estado
          </Button>
        </form>
      </section>

      {error !== null ? (
        <section className="vpg-tarjeta">
          <Alert
            tone="error"
            title={tituloDeError(error.status, error.code)}
            requestId={error.requestId}
            fields={error.fields}
          >
            <p>{error.message}</p>
            {error.code === "stale_mfa" ? (
              <p>
                El reset exige un MFA <em>reciente</em>: una sesión vieja no
                basta. Cierra la sesión, vuelve a entrar con tu código y
                repítelo.
              </p>
            ) : null}
            {error.status === 409 && typeof error.context["operation_id"] === "string" ? (
              <p>
                La operación quedó <strong>a medias</strong> y no se ha emitido
                otra semilla. Reconcíliala con su identificador:{" "}
                <code className="vpg-codigo-en-linea">
                  {String(error.context["operation_id"])}
                </code>{" "}
                (consulta{" "}
                <code className="vpg-codigo-en-linea">
                  GET /vault/operations/&#123;id&#125;
                </code>{" "}
                o <code className="vpg-codigo-en-linea">reconcile-operations.sh</code>).
              </p>
            ) : null}
            {error.status === 409 && error.code !== "partial_operation" ? (
              <p>
                No se genera una semilla nueva automáticamente: si hace falta
                sustituirla, usa el reset explícito de abajo.
              </p>
            ) : null}
          </Alert>
        </section>
      ) : null}

      {usuario !== null ? (
        <section className="vpg-tarjeta" aria-labelledby="titulo-estado">
          <h3 className="vpg-tarjeta__titulo" id="titulo-estado">
            Estado actual
          </h3>
          <dl className="vpg-datos">
            <dt>Usuario</dt>
            <dd>{usuario.username}</dd>
            <dt>Activo</dt>
            <dd>{usuario.is_active ? "sí" : "no"}</dd>
            <dt>Roles</dt>
            <dd>{usuario.role_codes.join(", ") || "sin roles"}</dd>
            <dt>Vínculo con Vault</dt>
            <dd>
              {usuario.vault_link
                ? `${usuario.vault_link.vault_username} · ${usuario.vault_link.totp_status}`
                : "sin vínculo: todavía no está aprovisionado"}
            </dd>
            {usuario.vault_link ? (
              <>
                <dt>Semilla generada</dt>
                <dd>{usuario.vault_link.totp_generated_at ?? "sin dato"}</dd>
                <dt>Confirmada</dt>
                <dd>{usuario.vault_link.totp_confirmed_at ?? "sin confirmar"}</dd>
                <dt>Último login MFA</dt>
                <dd>{usuario.vault_link.last_mfa_login_at ?? "ninguno"}</dd>
              </>
            ) : null}
          </dl>
          {usuario.vault_link?.notice ? (
            <p className="vpg-campo__ayuda">{usuario.vault_link.notice}</p>
          ) : null}
          <p className="vpg-campo__ayuda">
            Esta consulta es de solo lectura: no genera, no devuelve y no
            reinicia ninguna semilla. Un estado{" "}
            <code className="vpg-codigo-en-linea">pending</code> tampoco autoriza
            un reset por sí mismo.
          </p>
        </section>
      ) : null}

      {inscripcion !== null ? (
        <section className="vpg-tarjeta" aria-labelledby="titulo-inscripcion-admin">
          <h3 className="vpg-tarjeta__titulo" id="titulo-inscripcion-admin">
            Inscripción de {inscripcion.vault_username}
          </h3>
          <Alert tone="atencion" title="Se muestra una sola vez">
            <p>{inscripcion.warning}</p>
            <p className="vpg-aviso__meta">
              Operación {inscripcion.operation_id} · estado{" "}
              {inscripcion.totp_status}
            </p>
          </Alert>
          {inscripcion.totp_enrollment_uri ? (
            <EnrollmentQr
              uri={inscripcion.totp_enrollment_uri}
              username={inscripcion.vault_username}
              onClose={() => setInscripcion(null)}
            />
          ) : (
            <Alert tone="atencion" title="Sin URI que mostrar">
              <p>
                La respuesta no incluyó un URI de inscripción, así que no hay QR
                que dibujar. Si la persona necesita inscribirse, hace falta un
                reset explícito: la semilla anterior no se puede recuperar.
              </p>
            </Alert>
          )}
        </section>
      ) : null}

      <section className="vpg-tarjeta" aria-labelledby="titulo-provision">
        <h3 className="vpg-tarjeta__titulo" id="titulo-provision">
          Aprovisionar e inscribir
        </h3>
        <p className="vpg-tarjeta__intro">
          Crea la identidad en Vault y genera su primera semilla TOTP. Si esa
          identidad ya existe con semilla, esta operación no la sustituye: para
          eso está el reset.
        </p>
        <form onSubmit={aprovisionar} noValidate>
          <PasswordField
            label="Contraseña inicial en Vault"
            value={passwordInicial}
            autoComplete="new-password"
            required
            help="Se envía a Vault y no se guarda en PostgreSQL. Entrégala por un canal aparte del QR."
            onChange={(evento) => setPasswordInicial(evento.target.value)}
          />
          <TextField
            label="Usuario de Vault (opcional)"
            value={usuarioVault}
            autoComplete="off"
            spellCheck={false}
            help="Si se omite, se usa el username del empleado."
            onChange={(evento) => setUsuarioVault(evento.target.value)}
          />
          <Button
            type="submit"
            busy={tarea === "provision"}
            busyLabel="Aprovisionando..."
            disabled={passwordInicial.length === 0}
          >
            Aprovisionar y mostrar el QR
          </Button>
        </form>
      </section>

      <section className="vpg-tarjeta" aria-labelledby="titulo-reset">
        <h3 className="vpg-tarjeta__titulo" id="titulo-reset">
          Reset del segundo factor
        </h3>
        <p className="vpg-tarjeta__intro">
          Destruye la semilla de esa persona, invalida sus sesiones y genera una
          nueva inscripción. Exige rol <code className="vpg-codigo-en-linea">admin</code>,
          un MFA reciente y la confirmación escrita que pide el contrato. Nunca
          se ejecuta solo.
        </p>
        <form onSubmit={reiniciar} noValidate>
          <TextField
            label="Motivo"
            value={motivo}
            maxLength={200}
            required
            help="Queda en la auditoría. Entre 3 y 200 caracteres."
            onChange={(evento) => setMotivo(evento.target.value)}
          />
          <TextField
            label='Escribe "RESET" para confirmar'
            value={confirmacion}
            autoComplete="off"
            spellCheck={false}
            onChange={(evento) => setConfirmacion(evento.target.value.toUpperCase())}
          />
          <Button
            type="submit"
            variante="peligro"
            busy={tarea === "reset"}
            busyLabel="Reiniciando..."
            disabled={confirmacion !== "RESET" || motivo.trim().length < 3}
          >
            Reiniciar el segundo factor
          </Button>
        </form>
      </section>

      <p className="vpg-pie">
        <Link to={ROUTES.inicio}>Volver al inicio</Link>
      </p>
    </>
  );
}

function tituloDeError(status: number, code: string): string {
  if (status === 401) return "La sesión ya no es válida";
  if (code === "stale_mfa") return "Hace falta un MFA reciente";
  if (status === 403) return "No tienes permiso para esta operación";
  if (status === 404) return "No existe ese empleado";
  if (code === "partial_operation") return "Operación parcial: hay que reconciliar";
  if (status === 409) return "Conflicto de estado";
  if (status === 422) return "Revisa los datos enviados";
  if (status === 429) return "Demasiadas peticiones";
  if (status === 503) return "El servicio no está disponible";
  if (status === 0) return "No se pudo contactar con el servicio";
  return "No se pudo completar la operación";
}
