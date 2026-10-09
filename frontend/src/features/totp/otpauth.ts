/**
 * Lectura **solo informativa** de un URI `otpauth://`.
 *
 * Esta funcion no reconstruye el URI, no lo normaliza y no lo modifica: el QR
 * se dibuja siempre con la cadena exacta que entrego el backend, de modo que
 * issuer, algoritmo, digits y period sean los que Vault genero. Lo que se
 * extrae aqui es para mostrar texto al lado del codigo.
 *
 * El parametro `secret` NO se devuelve. Que el URI entero lo contenga es
 * inevitable (es el formato), pero no hace falta pasearlo por mas sitios.
 */
export interface OtpauthInfo {
  cuenta: string;
  issuer: string | null;
  digits: string;
  period: string;
  algorithm: string;
}

/** True solo si parece un URI TOTP utilizable. No valida la semilla. */
export function esOtpauthTotp(uri: string): boolean {
  return /^otpauth:\/\/totp\//i.test(uri.trim());
}

export function leerOtpauth(uri: string): OtpauthInfo | null {
  if (!esOtpauthTotp(uri)) return null;
  try {
    const parsed = new URL(uri.trim());
    const etiqueta = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
    const [posibleIssuer, posibleCuenta] = etiqueta.split(":");
    const issuerParametro = parsed.searchParams.get("issuer");

    return {
      cuenta: (posibleCuenta ?? posibleIssuer ?? etiqueta).trim(),
      issuer: issuerParametro ?? (posibleCuenta ? (posibleIssuer ?? null) : null),
      digits: parsed.searchParams.get("digits") ?? "6",
      period: parsed.searchParams.get("period") ?? "30",
      algorithm: parsed.searchParams.get("algorithm") ?? "SHA1",
    };
  } catch {
    return null;
  }
}
