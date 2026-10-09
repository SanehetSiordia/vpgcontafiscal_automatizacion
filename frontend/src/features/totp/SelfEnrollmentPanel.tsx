import { useEffect, useRef, useState } from "react";

import { Alert } from "../../shared/ui/Alert";
import { Button } from "../../shared/ui/Button";
import { useAuth } from "../auth/state/AuthContext";
import { toAuthError, type AuthError } from "../auth/state/reducer";
import type { SelfEnrollmentOut } from "../auth/types";
import { EnrollmentQr } from "./EnrollmentQr";

const SIN_QR =
  "El QR de inscripción no está disponible. Solicita al administrador la " +
  "configuración de tu autenticador.";

/**
 * Inscripción inicial del propio TOTP, dentro de la pantalla del código.
 *
 * Solo aparece si el backend entregó una autorización de inscripción en el paso
 * 1, es decir si el estado histórico no es `confirmed` ni `disabled`. Nada se
 * dispara solo: hace falta un clic explícito, y la autorización es de un solo
 * uso tanto en el servidor como aquí.
 *
 * Que esta opción esté visible **no** significa que haya una semilla por
 * generar: si la entidad ya tiene una, el servidor responde 409 y lo que se
 * muestra es el camino del reset administrativo, no un segundo intento.
 */
export function SelfEnrollmentPanel() {
  const { state, enrollTotp } = useAuth();
  const [inscripcion, setInscripcion] = useState<SelfEnrollmentOut | null>(null);
  const [error, setError] = useState<AuthError | null>(null);
  const [cargando, setCargando] = useState(false);
  const enCurso = useRef(false);

  const challengeId = state.challenge?.challenge_id ?? null;
  const enrollmentId = state.challenge?.enrollment_id ?? null;

  useEffect(() => {
    // Cambiar de desafío es cambiar de intento de acceso (y posiblemente de
    // persona): la inscripción anterior no debe seguir en pantalla.
    setInscripcion(null);
    setError(null);
  }, [challengeId]);

  if (state.challenge === null) return null;

  const pedirInscripcion = async (): Promise<void> => {
    if (enCurso.current) return;
    enCurso.current = true;
    setCargando(true);
    setError(null);
    try {
      setInscripcion(await enrollTotp());
    } catch (fallo) {
      setError(toAuthError(fallo));
    } finally {
      setCargando(false);
      enCurso.current = false;
    }
  };

  if (inscripcion !== null) {
    return (
      <>
        <Alert tone="info" title="Inscripción generada una sola vez">
          <p>{inscripcion.warning}</p>
        </Alert>
        <EnrollmentQr
          uri={inscripcion.totp_enrollment_uri}
          username={inscripcion.username}
          onClose={() => setInscripcion(null)}
        />
      </>
    );
  }

  if (error !== null) {
    const yaInscrito = error.code === "totp_already_enrolled";
    return (
      <Alert
        tone={yaInscrito ? "atencion" : "error"}
        title={
          yaInscrito
            ? "Ya existe una inscripción para esta identidad"
            : "No se pudo generar la inscripción"
        }
        requestId={error.requestId}
        fields={error.fields}
      >
        <p>{error.message}</p>
        {yaInscrito ? (
          <>
            <p>{SIN_QR}</p>
            <p>
              Si tu autenticador ya tiene la cuenta, introduce el código de seis
              dígitos arriba: no hace falta nada más. Si lo perdiste, la semilla
              no se puede recuperar y hace falta un reset administrativo
              explícito.
            </p>
          </>
        ) : (
          <p>
            No se ha reintentado solo. Puedes volver a intentarlo tras repetir el
            acceso, o introducir el código arriba si tu autenticador ya tiene la
            cuenta.
          </p>
        )}
      </Alert>
    );
  }

  if (enrollmentId === null) {
    return (
      <Alert tone="info" title="¿Tu autenticador todavía no tiene la cuenta?">
        <p>{SIN_QR}</p>
        <p>
          Esta pantalla no puede generar una inscripción ahora mismo: o tu
          segundo factor ya está confirmado, o la autorización de inscripción ya
          se usó en este acceso.
        </p>
      </Alert>
    );
  }

  return (
    <section aria-labelledby="titulo-inscripcion">
      <hr className="vpg-separador" />
      <h3 id="titulo-inscripcion" className="vpg-tarjeta__titulo">
        ¿Tu autenticador todavía no tiene la cuenta?
      </h3>
      <p className="vpg-tarjeta__intro">
        Si ya la tiene, introduce el código de arriba y no necesitas esto. Si no
        la tiene, genera la inscripción inicial: se muestra <strong>una sola
        vez</strong> y no entrega ninguna sesión por sí misma.
      </p>
      <div className="vpg-acciones">
        <Button
          variante="secundario"
          busy={cargando}
          busyLabel="Generando..."
          onClick={() => void pedirInscripcion()}
        >
          Mostrar mi código QR de inscripción
        </Button>
      </div>
    </section>
  );
}
