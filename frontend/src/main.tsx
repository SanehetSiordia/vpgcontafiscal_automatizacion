import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { App } from "./app/App";
import { AuthProvider } from "./features/auth/state/AuthProvider";
import "./shared/ui/styles.css";

/**
 * `StrictMode` queda activado a propósito: monta cada componente dos veces en
 * desarrollo, y eso es justo lo que destapa un efecto que repita un login, una
 * verificación o una inscripción. Si alguna de esas operaciones se moviera a un
 * `useEffect`, aquí se vería.
 */
const raiz = document.getElementById("raiz");
if (raiz === null) {
  throw new Error("No existe el contenedor #raiz en index.html");
}

createRoot(raiz).render(
  <StrictMode>
    <BrowserRouter
      // Los dos comportamientos de la v7 se activan ya: evitan los avisos de
      // transicion en la consola y dejan el salto de version sin sorpresas.
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
    >
      <AuthProvider>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
