import { QRCodeSVG } from "qrcode.react";
import { useEffect, useState } from "react";

import { ENROLLMENT_VISIBLE_SECONDS } from "../../shared/config/env";
import { Alert } from "../../shared/ui/Alert";
import { Button } from "../../shared/ui/Button";
import { esOtpauthTotp, leerOtpauth } from "./otpauth";

/**
 * QR de inscripcion TOTP.
 *
 * Reglas que este componente hace cumplir:
 *
 *  * **El URI vive solo aqui.** Llega por props desde el componente que lo
 *    pidio y no se guarda en estado global, ni en almacenamiento del navegador,
 *    ni en la URL, ni en el historial. Al desmontar, desaparece.
 *  * **Se dibuja la cadena exacta del backend.** Nada de recomponerla: issuer,
 *    algoritmo, digits y period son los de Vault. Si no parece un `otpauth://`
 *    TOTP, no se dibuja un QR: se dice que la respuesta no es utilizable. Un QR
 *    inventado seria peor que ninguno.
 *  * **Se oculta solo.** Pasado `ENROLLMENT_VISIBLE_SECONDS` el componente se
 *    cierra. Eso oculta la pantalla y nada mas: la semilla sigue siendo valida
 *    en Vault, y por eso el texto no promete lo contrario.
 *  * **Sin descarga, sin copia automatica y sin servicio externo.** La libreria
 *    dibuja un SVG local; no hay peticion a ningun generador de imagenes.
 */
export function EnrollmentQr({
  uri,
  username,
  onClose,
}: {
  uri: string;
  username: string;
  onClose: () => void;
}) {
  const [restante, setRestante] = useState(ENROLLMENT_VISIBLE_SECONDS);

  useEffect(() => {
    // Cuenta atras local. No hace peticiones, asi que repetirla por un doble
    // montaje de StrictMode no tiene efecto observable.
    const tic = window.setInterval(() => {
      setRestante((valor) => (valor <= 1 ? 0 : valor - 1));
    }, 1000);
    return () => window.clearInterval(tic);
  }, []);

  useEffect(() => {
    if (restante === 0) onClose();
  }, [restante, onClose]);

  if (!esOtpauthTotp(uri)) {
    return (
      <Alert tone="error" title="La inscripción recibida no es utilizable">
        <p>
          El servicio devolvio una cadena que no es un URI{" "}
          <code className="vpg-codigo-en-linea">otpauth://totp/</code>. No se
          dibuja ningún código: un QR inventado no inscribiría nada. Avisa al
          administrador para que revise la configuración de MFA en Vault.
        </p>
      </Alert>
    );
  }

  const info = leerOtpauth(uri);

  return (
    <section className="vpg-qr" aria-labelledby="titulo-qr">
      <h3 id="titulo-qr" className="vpg-oculto-visual">
        Código QR de inscripción para {username}
      </h3>
      <ol className="vpg-qr__pasos">
        <li>Abre Google Authenticator en tu celular.</li>
        <li>
          Pulsa <strong>Añadir cuenta</strong>.
        </li>
        <li>
          Elige <strong>Escanear código QR</strong> y apunta a este código.
        </li>
      </ol>
      <div className="vpg-qr__lienzo">
        <QRCodeSVG
          value={uri}
          size={232}
          level="M"
          marginSize={2}
          bgColor="#ffffff"
          fgColor="#15222e"
          title={`Inscripción TOTP de ${username}`}
        />
      </div>
      {info ? (
        <p className="vpg-qr__cuenta">
          Cuenta <strong>{info.cuenta}</strong>
          {info.issuer ? <> · emisor {info.issuer}</> : null} · {info.digits}{" "}
          dígitos · {info.period} s · {info.algorithm}
        </p>
      ) : null}
      <p className="vpg-qr__cuenta">
        Se oculta en {restante} s. Ocultarlo no caduca la semilla en Vault: si
        hace falta volver a verlo, se necesita un reset administrativo
        explícito.
      </p>
      <details className="vpg-detalle">
        <summary>Configuración manual (mostrar el URI completo)</summary>
        <p>
          Solo si el celular no puede escanear. El URI contiene la semilla: no
          lo copies a un chat, a un correo ni a un archivo.
        </p>
        <code className="vpg-uri">{uri}</code>
      </details>
      <Button variante="secundario" onClick={onClose}>
        Ya lo escaneé: ocultar el código
      </Button>
    </section>
  );
}
