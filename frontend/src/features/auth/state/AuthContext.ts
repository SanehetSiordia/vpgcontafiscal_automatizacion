import { createContext, useContext } from "react";

import type { SelfEnrollmentOut } from "../types";
import type { AuthState } from "./reducer";

/**
 * Contrato que el proveedor expone a las pantallas.
 *
 * `enrollTotp` **devuelve** la inscripcion en vez de guardarla en el estado
 * global: el URI otpauth y su QR deben vivir solo en la memoria del componente
 * que los muestra, para que desaparezcan al desmontarlo.
 */
export interface AuthContextValue {
  state: AuthState;
  signIn(username: string, password: string): Promise<void>;
  submitCode(code: string): Promise<void>;
  enrollTotp(): Promise<SelfEnrollmentOut>;
  signOut(): Promise<void>;
  backToLogin(): void;
  clearFeedback(): void;
  /** Para el resto de features: un 401 en una operacion autenticada. */
  reportAuthFailure(error: unknown): void;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (value === null) {
    throw new Error("useAuth se ha usado fuera de <AuthProvider>");
  }
  return value;
}
