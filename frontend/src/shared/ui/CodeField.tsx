import { useId, type ClipboardEvent } from "react";

/**
 * Campo del codigo TOTP de seis digitos.
 *
 * Decisiones que importan:
 *
 *  * **Es un `string`, no un numero.** Un `number` perderia los ceros a la
 *    izquierda, y "012345" es un codigo perfectamente valido.
 *  * **Un solo campo, no seis casillas.** Seis casillas obligan a logica de
 *    foco y rompen el pegado y el autorrelleno. Con `autoComplete` en
 *    `one-time-code`, el movil ofrece el codigo del portapapeles.
 *  * **No se genera ni se valida el TOTP aqui.** React solo recoge digitos:
 *    quien dice si el codigo vale es Vault, a traves de user-mgmt.
 *  * **No se envia nada al teclear.** El envio es explicito, para no gastar un
 *    desafio con un codigo a medio escribir.
 */
export function CodeField({
  value,
  onChange,
  disabled,
  error,
}: {
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  error?: string | null;
}) {
  const id = useId();
  const idAyuda = `${id}-ayuda`;
  const idError = `${id}-error`;

  const soloDigitos = (texto: string): string =>
    texto.replace(/\D/g, "").slice(0, 6);

  const alPegar = (evento: ClipboardEvent<HTMLInputElement>): void => {
    // Un codigo pegado suele llegar con espacios ("123 456").
    const pegado = evento.clipboardData.getData("text");
    if (pegado) {
      evento.preventDefault();
      onChange(soloDigitos(pegado));
    }
  };

  return (
    <div className="vpg-campo">
      <label className="vpg-campo__etiqueta" htmlFor={id}>
        Código de seis dígitos
      </label>
      <input
        id={id}
        className="vpg-entrada vpg-codigo"
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        autoCorrect="off"
        spellCheck={false}
        enterKeyHint="done"
        pattern="[0-9]*"
        maxLength={6}
        value={value}
        disabled={disabled}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${idAyuda} ${idError}` : idAyuda}
        onChange={(evento) => onChange(soloDigitos(evento.target.value))}
        onPaste={alPegar}
      />
      <span className="vpg-campo__ayuda" id={idAyuda}>
        Lo genera tu aplicación autenticadora en el celular. Se conserva tal cual
        se escribe, incluidos los ceros iniciales.
      </span>
      {error ? (
        <span className="vpg-campo__error" id={idError}>
          {error}
        </span>
      ) : null}
    </div>
  );
}
