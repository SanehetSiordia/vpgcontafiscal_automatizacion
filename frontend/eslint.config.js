import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

/**
 * Ademas de las reglas habituales, aqui hay tres prohibiciones propias de esta
 * etapa, y ninguna es decorativa:
 *
 *   * `no-restricted-globals` / `no-restricted-properties` sobre
 *     localStorage, sessionStorage e indexedDB: la sesion y la inscripcion
 *     viven SOLO en memoria. Recargar debe exigir un login nuevo.
 *   * `no-console`: ningun valor sensible (Authorization, contrasena, codigo,
 *     challenge_id, api_session, URI otpauth) debe acabar en la consola.
 *   * `react/no-danger` no existe sin el plugin de React, asi que se prohibe
 *     `dangerouslySetInnerHTML` por nombre de propiedad.
 */
export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      "no-console": "error",
      "no-restricted-globals": [
        "error",
        {
          name: "localStorage",
          message:
            "La sesion vive solo en memoria: no se persiste en el navegador.",
        },
        {
          name: "sessionStorage",
          message:
            "La sesion vive solo en memoria: no se persiste en el navegador.",
        },
        {
          name: "indexedDB",
          message: "Ni sesiones ni URI de inscripcion se guardan en IndexedDB.",
        },
      ],
      "no-restricted-properties": [
        "error",
        {
          object: "window",
          property: "localStorage",
          message: "La sesion vive solo en memoria.",
        },
        {
          object: "window",
          property: "sessionStorage",
          message: "La sesion vive solo en memoria.",
        },
      ],
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "Nada de innerHTML con datos del backend: se renderiza como texto.",
        },
      ],
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // La infraestructura de pruebas SI toca el almacenamiento del navegador:
    // es justamente quien vigila que la aplicacion no lo use.
    files: ["src/test/**/*.{ts,tsx}"],
    rules: {
      "no-restricted-globals": "off",
      "no-restricted-properties": "off",
    },
  },
  {
    files: ["vite.config.ts", "eslint.config.js"],
    extends: [js.configs.recommended],
    languageOptions: { globals: globals.node },
    rules: { "no-console": "off" },
  },
);
