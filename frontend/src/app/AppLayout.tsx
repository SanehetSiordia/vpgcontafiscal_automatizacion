import type { ReactNode } from "react";

import { useAuth } from "../features/auth/state/AuthContext";

const ETIQUETAS: Record<string, string> = {
  anonymous: "sin sesión",
  logging_in: "comprobando contraseña",
  mfa_required: "pendiente del segundo factor",
  verifying_mfa: "validando el código",
  authenticated: "sesión activa",
  logging_out: "cerrando sesión",
};

/**
 * Marco de la aplicación: cabecera, contenido y pie.
 *
 * La cabecera muestra el estado de la máquina de estados tal cual, sin
 * adornarlo: "pendiente del segundo factor" no es "sesión iniciada", y que se
 * lea distinto es justamente el punto.
 */
export function AppLayout({ children }: { children: ReactNode }) {
  const { state } = useAuth();

  return (
    <div className="vpg-app">
      <a className="vpg-salto-contenido" href="#contenido">
        Saltar al contenido
      </a>
      <header className="vpg-cabecera">
        <p className="vpg-cabecera__marca">VPG Contadores</p>
        <p className="vpg-cabecera__nota" aria-live="polite">
          Estado: {ETIQUETAS[state.status] ?? state.status}
        </p>
      </header>
      <main className="vpg-principal" id="contenido">
        {children}
      </main>
      <footer className="vpg-pie">
        Entorno local del despacho. Las sesiones viven en memoria: al recargar
        hay que iniciar sesión otra vez.
      </footer>
    </div>
  );
}
