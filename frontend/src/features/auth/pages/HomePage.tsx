import { Link } from "react-router-dom";

import { ROUTES } from "../../../shared/config/env";
import { Alert } from "../../../shared/ui/Alert";
import { Button } from "../../../shared/ui/Button";
import { useAuth } from "../state/AuthContext";
import { isAdmin } from "../types";

function fecha(iso: string | null): string {
  if (!iso) return "sin dato";
  const valor = new Date(iso);
  if (Number.isNaN(valor.getTime())) return iso;
  return valor.toLocaleString("es-MX", { dateStyle: "medium", timeStyle: "medium" });
}

/**
 * Pantalla de inicio: deliberadamente mínima.
 *
 * No es un panel de módulos futuros. Muestra quién eres según el **backend**
 * (`/auth/me`), en qué estado está tu sesión y cómo cerrarla. Los enlaces a
 * otras funciones aparecerán cuando esas funciones existan.
 */
export function HomePage() {
  const { state, signOut } = useAuth();
  const principal = state.principal;
  const cerrando = state.status === "logging_out";

  return (
    <>
      <section className="vpg-tarjeta" aria-labelledby="titulo-inicio">
        <h2 className="vpg-tarjeta__titulo" id="titulo-inicio">
          Bienvenido{principal?.username ? `, ${principal.username}` : ""}
        </h2>
        <p className="vpg-tarjeta__intro">
          Tu sesión está activa. Es un identificador opaco que vive solo en la
          memoria de este navegador y de un único worker del servicio: al
          recargar la página o reiniciar el backend habrá que iniciar sesión otra
          vez.
        </p>

        <dl className="vpg-datos">
          <dt>Usuario</dt>
          <dd>{principal?.username ?? "sin dato"}</dd>

          <dt>Identificador</dt>
          <dd>
            <code>{principal?.user_id ?? "sin dato"}</code>
          </dd>

          <dt>Roles de aplicación</dt>
          <dd>
            {principal && principal.role_codes.length > 0 ? (
              <ul className="vpg-etiquetas">
                {principal.role_codes.map((rol) => (
                  <li className="vpg-etiqueta" key={rol}>
                    {rol}
                  </li>
                ))}
              </ul>
            ) : (
              "sin roles asignados"
            )}
          </dd>

          <dt>Políticas de Vault</dt>
          <dd>
            {principal && principal.vault_policies.length > 0 ? (
              <ul className="vpg-etiquetas">
                {principal.vault_policies.map((politica) => (
                  <li className="vpg-etiqueta" key={politica}>
                    {politica}
                  </li>
                ))}
              </ul>
            ) : (
              "sin dato"
            )}
          </dd>

          <dt>Entidad de Vault</dt>
          <dd>
            <code>{principal?.entity_id ?? "sin dato"}</code>
          </dd>

          <dt>La sesión caduca</dt>
          <dd>{fecha(state.expiresAt)}</dd>

          <dt>Antigüedad del MFA</dt>
          <dd>
            {principal ? `${Math.round(principal.mfa_age_seconds)} s` : "sin dato"}{" "}
            <span className="vpg-campo__ayuda">
              Las operaciones destructivas exigen un MFA reciente; si el tuyo
              envejece, el servidor pedirá otro acceso.
            </span>
          </dd>
        </dl>

        <p className="vpg-campo__ayuda">
          Los roles y permisos los decide el backend en cada petición: esta
          pantalla solo los muestra.
        </p>

        <div className="vpg-acciones">
          <Button
            variante="primario"
            busy={cerrando}
            busyLabel="Cerrando..."
            onClick={() => void signOut()}
          >
            Cerrar sesión
          </Button>
        </div>
      </section>

      {isAdmin(principal) ? (
        <section className="vpg-tarjeta" aria-labelledby="titulo-herramientas">
          <h2 className="vpg-tarjeta__titulo" id="titulo-herramientas">
            Herramientas de administración
          </h2>
          <p className="vpg-tarjeta__intro">
            Disponible solo con rol <code className="vpg-codigo-en-linea">admin</code>.
            El backend vuelve a comprobarlo en cada petición: este enlace es una
            comodidad de navegación, no el control de acceso.
          </p>
          <p>
            <Link to={ROUTES.totp}>Inscripción TOTP de un empleado</Link>
          </p>
        </section>
      ) : null}

      <Alert tone="info" title="Alcance de esta versión">
        <p>
          Esta etapa implementa el acceso y la inscripción del segundo factor. El
          CRUD de empleados, los secretos, los consumidores y el crawler no
          forman parte de ella y no se muestran como si existieran.
        </p>
      </Alert>
    </>
  );
}
