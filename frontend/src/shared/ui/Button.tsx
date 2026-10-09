import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variante = "primario" | "secundario" | "peligro" | "sutil";

/**
 * Boton con estado de trabajo en curso.
 *
 * `busy` deshabilita **y** marca `aria-busy`, de modo que un segundo envio no
 * depende de que la persona vea el cambio visual. El candado real esta ademas
 * en el proveedor de autenticacion: esto es la primera barrera, no la unica.
 */
export function Button({
  variante = "primario",
  busy = false,
  busyLabel,
  children,
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variante?: Variante;
  busy?: boolean;
  busyLabel?: string;
  children: ReactNode;
}) {
  return (
    <button
      {...rest}
      className={`vpg-boton vpg-boton--${variante}`}
      disabled={disabled === true || busy}
      aria-busy={busy}
    >
      {busy ? (busyLabel ?? "Procesando...") : children}
    </button>
  );
}
