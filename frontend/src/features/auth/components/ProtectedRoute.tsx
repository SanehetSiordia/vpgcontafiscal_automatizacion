import type { ReactElement } from "react";
import { Navigate } from "react-router-dom";

import { ROUTES } from "../../../shared/config/env";
import { Alert } from "../../../shared/ui/Alert";
import { useAuth } from "../state/AuthContext";
import { isAdmin } from "../types";

/**
 * Compuerta de navegación, **no** de autorización.
 *
 * Evita que alguien aterrice en una pantalla vacía o que pida datos sin sesión,
 * y nada más: quien autoriza es el backend, que vuelve a comprobar sesión, rol
 * y permiso por objeto en cada petición. Quitar esto no abriría ningún dato;
 * dejarlo no sustituye a ninguna comprobación del servidor.
 */
export function ProtectedRoute({
  children,
  requireAdmin = false,
}: {
  children: ReactElement;
  requireAdmin?: boolean;
}) {
  const { state } = useAuth();

  if (state.status !== "authenticated") {
    return (
      <Navigate to={ROUTES.login} replace state={{ sesionRequerida: true }} />
    );
  }

  if (requireAdmin && !isAdmin(state.principal)) {
    return (
      <Alert tone="error" title="Esta herramienta es solo para administradores">
        <p>
          Tu sesión es válida, pero tu rol de aplicación no incluye{" "}
          <code className="vpg-codigo-en-linea">admin</code>. El servidor
          rechazaría igualmente estas operaciones: aquí solo se evita el viaje.
        </p>
      </Alert>
    );
  }

  return children;
}
