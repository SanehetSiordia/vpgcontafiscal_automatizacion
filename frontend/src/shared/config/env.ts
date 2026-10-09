/**
 * Ajustes publicos del cliente. Aqui no hay secretos y no puede haberlos: todo
 * lo que este archivo contenga acaba en el paquete que descarga el navegador.
 *
 * `API_PREFIX` es **relativo a proposito**. El navegador llama al mismo origen
 * que sirvio la pagina y es Nginx quien reenvia ese prefijo a
 * `http://user-mgmt-service:8000/user_mgmt/v1/...` dentro de la red de Docker.
 * Asi no hay CORS, no hay contenido mixto al activar HTTPS y la API no necesita
 * publicarse en la LAN.
 *
 * Consecuencia que conviene tener presente: este valor es **de tiempo de
 * construccion**. Anadir variables `VITE_*` al contenedor estatico no cambia
 * nada, porque el paquete ya esta compilado; haria falta reconstruir la imagen.
 * Lo que si se cambia en tiempo de ejecucion es la configuracion de Nginx
 * (puertos, TLS, alcance), que no vive aqui.
 */
export const API_PREFIX = "/api/user_mgmt/v1";

/** Rutas de la interfaz. Centralizadas para que los redirects no se desvien. */
export const ROUTES = {
  login: "/login",
  mfa: "/mfa",
  inicio: "/inicio",
  totp: "/configuracion-totp",
} as const;

/**
 * Tiempo que una inscripcion TOTP permanece visible en pantalla antes de
 * ocultarse sola, en segundos.
 *
 * Oculta la pantalla y nada mas: **no** caduca la semilla en Vault ni invalida
 * el enrolamiento. Es una medida contra el QR olvidado en un monitor, no un
 * control de seguridad del segundo factor.
 */
export const ENROLLMENT_VISIBLE_SECONDS = 180;
