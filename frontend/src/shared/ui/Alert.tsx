import type { ReactNode } from "react";

import type { FieldIssue } from "../api/errors";

export type AlertTone = "error" | "atencion" | "info";

/**
 * Aviso accesible.
 *
 * Los errores van con `role="alert"` (`aria-live="assertive"`), porque
 * interrumpen la tarea; el resto con `role="status"`, que no interrumpe. Los
 * campos invalidos se listan por **nombre y motivo**: el valor enviado no
 * aparece, ni aqui ni en el backend, porque puede ser una contrasena o un
 * codigo.
 */
export function Alert({
  tone,
  title,
  requestId,
  fields,
  children,
}: {
  tone: AlertTone;
  title?: string;
  requestId?: string | null;
  fields?: FieldIssue[];
  children?: ReactNode;
}) {
  const esError = tone === "error";
  return (
    <div
      className={`vpg-aviso vpg-aviso--${tone}`}
      role={esError ? "alert" : "status"}
      aria-live={esError ? "assertive" : "polite"}
    >
      {title ? <p className="vpg-aviso__titulo">{title}</p> : null}
      {children}
      {fields && fields.length > 0 ? (
        <ul className="vpg-aviso__lista">
          {fields.map((issue) => (
            <li key={`${issue.field}:${issue.reason}`}>
              <strong>{issue.field}</strong>: {issue.reason}
            </li>
          ))}
        </ul>
      ) : null}
      {requestId ? (
        <p className="vpg-aviso__meta">
          Referencia para el log del servicio: {requestId}
        </p>
      ) : null}
    </div>
  );
}
