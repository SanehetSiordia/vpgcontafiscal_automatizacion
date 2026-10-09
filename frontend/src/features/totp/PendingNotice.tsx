import { Alert } from "../../shared/ui/Alert";
import type { TotpStatus } from "../auth/types";

/**
 * Aviso del estado del segundo factor, antes de pedir el codigo.
 *
 * El estado es **historico**, y el texto lo refleja: `pending` no demuestra que
 * la persona no tenga su autenticador configurado (puede tenerlo desde el
 * primer dia y no haber iniciado sesion todavia), y `confirmed` no exime del
 * MFA, que se exige en cada acceso.
 *
 * Si el backend no informa el estado (no hay vinculo registrado, o una version
 * anterior del servicio), no se adivina: se da la instruccion general y se dice
 * que el estado no esta disponible.
 */
export function PendingNotice({ status }: { status: TotpStatus | null }) {
  if (status === "confirmed") return null;

  if (status === "pending") {
    return (
      <Alert tone="atencion" title="Segundo factor pendiente de confirmación">
        <p>
          Tu autenticación TOTP está pendiente de confirmación. Si aún no la
          configuraste, abre Google Authenticator en tu celular y escanea el
          código QR de inscripción que te proporcione el responsable. Si ya la
          configuraste, introduce el código de seis dígitos de la aplicación.
        </p>
      </Alert>
    );
  }

  if (status === "reset_required") {
    return (
      <Alert tone="atencion" title="Hay una inscripción nueva sin confirmar">
        <p>
          Un administrador reinició tu segundo factor, así que existe una semilla
          nueva pendiente de confirmación. Usa la inscripción que te entregó esa
          persona: la anterior ya no sirve. Si la perdiste, pídele un reset
          nuevo; aquí no se puede recuperar.
        </p>
      </Alert>
    );
  }

  if (status === "disabled") {
    return (
      <Alert tone="error" title="Segundo factor deshabilitado">
        <p>
          Tu segundo factor está deshabilitado, así que no puedes continuar como
          si estuviera activo. Habla con un administrador: hace falta una
          intervención suya para volver a dejarlo operativo.
        </p>
      </Alert>
    );
  }

  return (
    <Alert tone="info" title="Introduce el código de tu autenticador">
      <p>
        Abre Google Authenticator en tu celular y escribe el código de seis
        dígitos de la cuenta de VPG Contadores.
      </p>
      <p>
        El servicio no ha informado el estado de tu inscripción en esta
        respuesta, así que no se muestra ninguno: si el autenticador no tiene
        todavía la cuenta, pide la inscripción al administrador.
      </p>
    </Alert>
  );
}
