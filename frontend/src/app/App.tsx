import { Suspense, lazy } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { ProtectedRoute } from "../features/auth/components/ProtectedRoute";
import { HomePage } from "../features/auth/pages/HomePage";
import { LoginPage } from "../features/auth/pages/LoginPage";
import { MfaPage } from "../features/auth/pages/MfaPage";
import { ROUTES } from "../shared/config/env";
import { AppLayout } from "./AppLayout";

/**
 * La herramienta administrativa se carga aparte: no hace falta para iniciar
 * sesión, que es lo que hace todo el mundo y lo que conviene que cargue rápido.
 * El resto del árbol cabe de sobra en un solo paquete, así que no se parte por
 * partirlo.
 */
const TotpAdminPage = lazy(() =>
  import("../features/totp/pages/TotpAdminPage").then((modulo) => ({
    default: modulo.TotpAdminPage,
  })),
);

export function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path={ROUTES.login} element={<LoginPage />} />
        <Route path={ROUTES.mfa} element={<MfaPage />} />
        <Route
          path={ROUTES.inicio}
          element={
            <ProtectedRoute>
              <HomePage />
            </ProtectedRoute>
          }
        />
        <Route
          path={ROUTES.totp}
          element={
            <ProtectedRoute requireAdmin>
              <Suspense
                fallback={<p className="vpg-cargando">Cargando la herramienta...</p>}
              >
                <TotpAdminPage />
              </Suspense>
            </ProtectedRoute>
          }
        />
        {/* Cualquier otra ruta de interfaz vuelve al acceso. El fallback de
            Nginx sirve index.html en rutas profundas, y es aquí donde se
            decide qué pantalla toca. */}
        <Route path="*" element={<Navigate to={ROUTES.login} replace />} />
      </Routes>
    </AppLayout>
  );
}
