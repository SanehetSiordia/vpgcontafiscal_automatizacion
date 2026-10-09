import { useId, useState, type InputHTMLAttributes } from "react";

interface Comun {
  label: string;
  help?: string;
  error?: string | null;
}

type Props = Comun &
  Omit<InputHTMLAttributes<HTMLInputElement>, "className" | "id">;

/** Campo de texto con etiqueta asociada, ayuda y error ligados por `aria`. */
export function TextField({ label, help, error, ...rest }: Props) {
  const id = useId();
  const idAyuda = `${id}-ayuda`;
  const idError = `${id}-error`;
  const describedBy = [help ? idAyuda : null, error ? idError : null]
    .filter((value): value is string => value !== null)
    .join(" ");

  return (
    <div className="vpg-campo">
      <label className="vpg-campo__etiqueta" htmlFor={id}>
        {label}
      </label>
      <input
        {...rest}
        id={id}
        className="vpg-entrada"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
      />
      {help ? (
        <span className="vpg-campo__ayuda" id={idAyuda}>
          {help}
        </span>
      ) : null}
      {error ? (
        <span className="vpg-campo__error" id={idError}>
          {error}
        </span>
      ) : null}
    </div>
  );
}

/**
 * Contrasena con mostrar u ocultar.
 *
 * El boton cambia `type` y nada mas: el valor no se copia a ningun sitio, no se
 * guarda y no se registra. El estado de visibilidad vuelve a "oculto" en cuanto
 * el componente se desmonta, porque es estado local.
 */
export function PasswordField({ label, help, error, ...rest }: Props) {
  const [visible, setVisible] = useState(false);
  const id = useId();
  const idAyuda = `${id}-ayuda`;
  const idError = `${id}-error`;
  const describedBy = [help ? idAyuda : null, error ? idError : null]
    .filter((value): value is string => value !== null)
    .join(" ");

  return (
    <div className="vpg-campo">
      <label className="vpg-campo__etiqueta" htmlFor={id}>
        {label}
      </label>
      <div className="vpg-campo__fila">
        <input
          {...rest}
          id={id}
          type={visible ? "text" : "password"}
          className="vpg-entrada"
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
        />
        <button
          type="button"
          className="vpg-boton vpg-boton--sutil"
          onClick={() => setVisible((previo) => !previo)}
          aria-pressed={visible}
        >
          {visible ? "Ocultar" : "Mostrar"}
          <span className="vpg-oculto-visual"> la contraseña</span>
        </button>
      </div>
      {help ? (
        <span className="vpg-campo__ayuda" id={idAyuda}>
          {help}
        </span>
      ) : null}
      {error ? (
        <span className="vpg-campo__error" id={idError}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
