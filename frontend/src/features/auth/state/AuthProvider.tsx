import {
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  type ReactNode,
} from "react";

import { ApiError, NetworkError } from "../../../shared/api/errors";
import * as api from "../api";
import type { SelfEnrollmentOut } from "../types";
import { AuthContext, type AuthContextValue } from "./AuthContext";
import { initialState, reducer, toAuthError } from "./reducer";

/**
 * Proveedor de autenticacion.
 *
 * Tres decisiones que conviene no revertir sin pensarlo:
 *
 *  1. **Nada de efectos que autentiquen.** Ninguna de estas operaciones se
 *     lanza desde un `useEffect`: todas salen de un envio explicito de la
 *     persona. Es lo que hace que StrictMode, un rerender o volver atras en el
 *     navegador no repitan un login, una verificacion ni una inscripcion.
 *  2. **Un candado por operacion.** `enCurso` es una referencia, no estado: si
 *     hubiera que esperar a un rerender para cerrar la puerta, un doble clic
 *     rapido pasaria igualmente.
 *  3. **La sesion no se persiste.** No hay `localStorage`, ni cookie, ni
 *     `sessionStorage`. Recargar la pagina exige un login nuevo, y eso es el
 *     comportamiento correcto aqui: las sesiones viven en la memoria de un solo
 *     worker de user-mgmt y reiniciarlo las invalida de todas formas.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const enCurso = useRef(false);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => {
    // Solo al desmontar el arbol entero: corta lo que quedara en vuelo.
    return () => abort.current?.abort();
  }, []);

  const nuevoAbort = useCallback((): AbortSignal => {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    return controller.signal;
  }, []);

  const signIn = useCallback(
    async (username: string, password: string): Promise<void> => {
      if (enCurso.current) return;
      enCurso.current = true;
      dispatch({ type: "LOGIN_START" });
      try {
        const challenge = await api.login(
          { username, password },
          nuevoAbort(),
        );
        // La contrasena no se guarda en ningun sitio: sale del ambito aqui.
        dispatch({ type: "LOGIN_CHALLENGE", challenge });
      } catch (error) {
        if (error instanceof NetworkError && error.aborted) return;
        dispatch({ type: "LOGIN_FAILED", error: toAuthError(error) });
      } finally {
        enCurso.current = false;
      }
    },
    [nuevoAbort],
  );

  const submitCode = useCallback(
    async (code: string): Promise<void> => {
      const challenge = state.challenge;
      if (challenge === null || enCurso.current) return;
      enCurso.current = true;
      dispatch({ type: "MFA_START" });
      try {
        const session = await api.verifyMfa(
          { challenge_id: challenge.challenge_id, code },
          nuevoAbort(),
        );
        // El principal lo dice el backend, no el cliente: roles y permisos no
        // se deducen de la respuesta del login.
        const principal = await api.me(session.api_session, nuevoAbort());
        dispatch({ type: "SESSION_ESTABLISHED", session, principal });
      } catch (error) {
        if (error instanceof NetworkError && error.aborted) return;
        const detalle = toAuthError(error);
        const desafioPerdido =
          error instanceof ApiError &&
          (detalle.code === "challenge_expired" ||
            detalle.code === "session_expired" ||
            detalle.status === 403);
        dispatch(
          desafioPerdido
            ? { type: "CHALLENGE_LOST", error: detalle }
            : { type: "MFA_FAILED", error: detalle },
        );
      } finally {
        enCurso.current = false;
      }
    },
    [nuevoAbort, state.challenge],
  );

  const enrollTotp = useCallback(async (): Promise<SelfEnrollmentOut> => {
    const enrollmentId = state.challenge?.enrollment_id;
    if (!enrollmentId) {
      throw new ApiError({
        status: 0,
        code: "sin_autorizacion",
        message:
          "No hay una autorización de inscripción vigente. Repite el acceso " +
          "para obtener una.",
      });
    }
    const inscripcion = await api.selfEnrollTotp(enrollmentId);
    // Se retira del estado en cuanto se usa: es de un solo uso en el servidor
    // y no debe quedar un boton que prometa repetirla.
    dispatch({
      type: "ENROLLMENT_CONSUMED",
      totpStatus: inscripcion.totp_status,
    });
    return inscripcion;
  }, [state.challenge]);

  const signOut = useCallback(async (): Promise<void> => {
    const session = state.session;
    if (session === null || enCurso.current) return;
    enCurso.current = true;
    dispatch({ type: "LOGOUT_START" });
    try {
      const { status } = await api.logout(session, nuevoAbort());
      dispatch({
        type: "LOGOUT_DONE",
        notice:
          status === 204
            ? "Sesión cerrada: el servidor la eliminó y revocó su token de Vault."
            : "La sesión ya no existía en el servidor; aquí también se ha borrado.",
      });
    } catch {
      // Se borra el estado local igualmente, pero no se afirma lo que no se
      // sabe: sin respuesta del servidor no hay revocacion acreditada.
      dispatch({
        type: "LOGOUT_DONE",
        notice:
          "Se ha borrado la sesión en este navegador, pero no se ha podido " +
          "confirmar la revocación en el servidor: el token de Vault seguirá " +
          "vivo hasta que caduque su TTL.",
      });
    } finally {
      enCurso.current = false;
    }
  }, [nuevoAbort, state.session]);

  const backToLogin = useCallback(() => dispatch({ type: "BACK_TO_LOGIN" }), []);
  const clearFeedback = useCallback(
    () => dispatch({ type: "CLEAR_FEEDBACK" }),
    [],
  );

  const reportAuthFailure = useCallback((error: unknown) => {
    if (error instanceof ApiError && error.status === 401) {
      dispatch({
        type: "SESSION_LOST",
        notice:
          "Tu sesión ha caducado o se ha invalidado en el servidor. Vuelve a " +
          "iniciar sesión.",
      });
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      state,
      signIn,
      submitCode,
      enrollTotp,
      signOut,
      backToLogin,
      clearFeedback,
      reportAuthFailure,
    }),
    [
      state,
      signIn,
      submitCode,
      enrollTotp,
      signOut,
      backToLogin,
      clearFeedback,
      reportAuthFailure,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
