import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach, expect } from "vitest";

/**
 * Infraestructura de pruebas.
 *
 * Además de los matchers de jest-dom, aquí se vigila un invariante de la etapa:
 * **nada se persiste en el navegador**. Cualquier escritura en `localStorage`,
 * `sessionStorage` o IndexedDB durante una prueba la hace fallar, de modo que
 * no haga falta acordarse de comprobarlo en cada caso.
 */
const escrituras: string[] = [];

for (const almacen of [window.localStorage, window.sessionStorage]) {
  const original = almacen.setItem.bind(almacen);
  almacen.setItem = (clave: string, valor: string): void => {
    escrituras.push(clave);
    original(clave, valor);
  };
}

afterEach(() => {
  // Con `globals: false`, Testing Library no registra su limpieza automatica
  // (busca un afterEach global y no lo encuentra). Sin esto, el DOM de una
  // prueba sobrevive a la siguiente y las consultas encuentran duplicados.
  cleanup();

  const vistas = [...escrituras];
  escrituras.length = 0;
  window.localStorage.clear();
  window.sessionStorage.clear();
  expect(
    vistas,
    "la aplicacion ha escrito en el almacenamiento del navegador: la sesion y " +
      "la inscripcion deben vivir solo en memoria",
  ).toEqual([]);
});
