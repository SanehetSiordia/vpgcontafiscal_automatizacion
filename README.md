# vpgcontafiscal_automatizacion
Automatizacion Inteligente para contabilidad fiscal VPG

| Componente | Estado | Servicio |
|---|---|---|
| [1. HashiCorp Vault](readme/etapa-1-vault.md) | listo | `vault-service` |
| [2. PostgreSQL 17](readme/etapa-2-postgresql.md) | listo | `postgres-service` |
| [3. user-mgmt-service (FastAPI)](readme/etapa-3-user-mgmt-service.md) | listo | `user-mgmt-service` |
| [4. vault-mgmt-service (CRUD de secretos)](readme/etapa-4-vault-mgmt-service.md) | listo | `vault-mgmt-service` |
| 5. Frontend | **no implementado**: estas etapas terminan en el backend | — |
| 6. Crawler | **no implementado**: la etapa 4 entrega su *contrato de consumo*, no el crawler | — |

Este archivo es el **índice**. La documentación de cada etapa vive en
[`readme/`](readme/), un archivo por componente, para que cada uno se pueda leer
y revisar por separado.

---

## Qué hay en cada archivo

### [Etapa 1 · HashiCorp Vault](readme/etapa-1-vault.md)

El almacén de secretos: imagen sin modo dev, inicialización, **desbloqueo
manual**, KV v2, autenticación `userpass` con **MFA TOTP** y OIDC opcional,
persistencia del volumen y notas de seguridad.

### [Etapa 2 · PostgreSQL 17](readme/etapa-2-postgresql.md)

El modelo de empleados: esquema `employees`, **dos cuentas** con
responsabilidades separadas (`vpg_admin` propietaria, `vpg_app` de ejecución sin
DDL), matriz RBAC y el vínculo con las identidades de Vault.

- [Comprobaciones reproducibles (Git Bash)](readme/etapa-2-postgresql.md#comprobaciones-reproducibles-git-bash)
  — 11 secciones, incluidas la verificación interactiva de `userpass` + TOTP y
  la consulta de una ruta de Vault autorizada
- [Seguridad](readme/etapa-2-postgresql.md#seguridad)

### [Etapa 3 · user-mgmt-service](readme/etapa-3-user-mgmt-service.md)

La API de empleados en `127.0.0.1:8000`: login de dos pasos delegado a Vault,
sesiones opacas **en memoria**, CRUD de empleados y provisionamiento de
identidades.

- [Endpoints](readme/etapa-3-user-mgmt-service.md#endpoints)
- [Autenticación: cómo encajan Vault y PostgreSQL](readme/etapa-3-user-mgmt-service.md#autenticación-cómo-encajan-vault-y-postgresql)
- [Comprobaciones reproducibles (etapa 3)](readme/etapa-3-user-mgmt-service.md#comprobaciones-reproducibles-etapa-3)
- [Colección de Postman](readme/etapa-3-user-mgmt-service.md#colección-de-postman)
- [Pruebas unitarias](readme/etapa-3-user-mgmt-service.md#pruebas-unitarias)
- [Seguridad (etapa 3)](readme/etapa-3-user-mgmt-service.md#seguridad-etapa-3)

### [Etapa 4 · vault-mgmt-service](readme/etapa-4-vault-mgmt-service.md)

El CRUD dinámico de secretos en `127.0.0.1:8001`: colecciones con campos
tipados, registros completos en **KV v2** con CAS y versionado, pasarela interna
para autorizar con el token humano, entrega por **response wrapping** y el
contrato de consumo del futuro crawler.

- [Comprobaciones reproducibles (etapa 4)](readme/etapa-4-vault-mgmt-service.md#comprobaciones-reproducibles-etapa-4)
- [Pruebas unitarias (etapa 4)](readme/etapa-4-vault-mgmt-service.md#pruebas-unitarias-etapa-4)
- [Seguridad (etapa 4)](readme/etapa-4-vault-mgmt-service.md#seguridad-etapa-4)

---

## Puesta en marcha, en orden

Cada etapa depende de la anterior. El detalle de cada paso está en su archivo;
aquí solo está la secuencia y dónde buscarla.

| # | Paso | Dónde |
|---|---|---|
| 1 | Secretos de PostgreSQL (`prepare-secrets.sh`) | [etapa 2](readme/etapa-2-postgresql.md#comprobaciones-reproducibles-git-bash) |
| 2 | Construir y arrancar Vault y PostgreSQL | [etapa 1](readme/etapa-1-vault.md), [etapa 2](readme/etapa-2-postgresql.md) |
| 3 | Inicializar Vault y **desbloquearlo a mano** | [etapa 1](readme/etapa-1-vault.md) |
| 4 | Habilitar KV v2, `userpass` + MFA TOTP y el administrador | [etapa 1](readme/etapa-1-vault.md) |
| 5 | AppRole y política de `user-mgmt`, migraciones 001 y 002 | [etapa 3](readme/etapa-3-user-mgmt-service.md#comprobaciones-reproducibles-etapa-3) |
| 6 | Migración 003, credencial interna y políticas KV del catálogo | [etapa 4](readme/etapa-4-vault-mgmt-service.md#1-preparación-por-cli) |
| 7 | `docker compose up -d` y comprobar salud de las dos APIs | [etapa 4](readme/etapa-4-vault-mgmt-service.md#3-arrancar) |
| 8 | Recorrido interactivo de comprobación: `bash scripts/vault_mgmt/walkthrough.sh` | [etapa 4](readme/etapa-4-vault-mgmt-service.md#6--interactivo--recorrido-crud-completo) |

> **Tras cada reinicio de Vault hay que volver a desbloquearlo.** Es un paso
> manual a propósito: ninguna de las dos APIs hace `unseal`. Mientras siga
> sellado, `/health/ready` responde 503 y dice exactamente qué falta.

---

## Mapa rápido: dónde se responde cada cosa

| Si buscas... | Mira en |
|---|---|
| Desbloquear Vault, KV v2, enrolar el TOTP del administrador | [etapa 1](readme/etapa-1-vault.md) |
| Esquema `employees`, las dos cuentas de PostgreSQL, matriz RBAC | [etapa 2](readme/etapa-2-postgresql.md) |
| Verificar `userpass` + TOTP de forma interactiva | [etapa 2 · comprobación 10](readme/etapa-2-postgresql.md#comprobaciones-reproducibles-git-bash) |
| Login de dos pasos, sesiones en memoria, CRUD de empleados | [etapa 3](readme/etapa-3-user-mgmt-service.md) |
| Provisionar una identidad de Vault para un empleado | [etapa 3 · Endpoints](readme/etapa-3-user-mgmt-service.md#endpoints) |
| Colecciones, esquemas versionados, registros, CAS y versiones | [etapa 4](readme/etapa-4-vault-mgmt-service.md) |
| Cómo se autorizan las operaciones entre los dos servicios | [etapa 4 · la pasarela interna](readme/etapa-4-vault-mgmt-service.md#autenticación-entre-procesos-la-pasarela-interna) |
| Reautenticación MFA para `destroy` y `purge` | [etapa 4](readme/etapa-4-vault-mgmt-service.md#reautenticación-mfa-para-lo-irreversible) |
| Mapeo rol de aplicación ↔ política de Vault | [etapa 4](readme/etapa-4-vault-mgmt-service.md#permisos-y-mapeo-rol--política-de-vault) |
| Entrega de secretos y qué **no** es el response wrapping | [etapa 4](readme/etapa-4-vault-mgmt-service.md#entrega-de-secretos) |
| Contrato del futuro crawler | [etapa 4](readme/etapa-4-vault-mgmt-service.md#contrato-del-futuro-crawler-una-máquina-independiente) |
| Recorrer el CRUD de secretos de punta a punta | [etapa 4 · comprobación 6](readme/etapa-4-vault-mgmt-service.md#6--interactivo--recorrido-crud-completo) (`walkthrough.sh`) |
| Un fallo parcial y cómo reconciliarlo | [etapa 4 · comprobación 9](readme/etapa-4-vault-mgmt-service.md#9-fallo-parcial-y-reconciliación) |
| Importar secretos que ya existían en Vault | [etapa 4 · comprobación 10](readme/etapa-4-vault-mgmt-service.md#10-inventario-e-importación-de-secretos-anteriores) |
| Qué demuestra cada suite de pruebas y qué no | [etapa 3](readme/etapa-3-user-mgmt-service.md#pruebas-unitarias), [etapa 4](readme/etapa-4-vault-mgmt-service.md#pruebas-unitarias-etapa-4) |
| Límites conocidos y decisiones discutibles de cada etapa | la sección «Seguridad» de [2](readme/etapa-2-postgresql.md#seguridad), [3](readme/etapa-3-user-mgmt-service.md#seguridad-etapa-3) y [4](readme/etapa-4-vault-mgmt-service.md#seguridad-etapa-4) |

---

## Estructura del repositorio

| Ruta | Qué contiene |
|---|---|
| `readme/` | La documentación por etapas que indexa este archivo |
| `app/` | Las dos aplicaciones: `app/` (user-mgmt) y `app/vault_mgmt/`, con módulos compartidos en `app/core/` |
| `sql/` | Migraciones numeradas: `001_employees.sql`, `002_vault_operations.sql`, `003_vault_mgmt.sql` |
| `scripts/` | Preparación por CLI, agrupada por componente (`postgres/`, `user_mgmt/`, `vault_mgmt/`) |
| `config/` | `vault.hcl` y las políticas de Vault en `config/policies/` |
| `requirements/` | Dependencias fijadas, un archivo por componente y por entorno |
| `tests/` | `tests/` (etapa 3) y `tests/vault_mgmt/` (etapa 4) |
| `postman/` | Colecciones y environments, uno por API |
| `secrets/` | Archivos de Compose secret. **Fuera de Git y del contexto de build** |

---

## Tres reglas que atraviesan todas las etapas

Están justificadas en cada archivo; aquí solo quedan enunciadas, porque
condicionan cómo se opera el proyecto entero.

1. **El desbloqueo de Vault es manual.** Ningún servicio hace `unseal`. Si una
   dependencia falta, el proceso arranca igualmente y responde 503 en readiness
   con el detalle: lo contrario dejaría sin diagnóstico el caso más común.
2. **Ninguna aplicación emite DDL.** No hay `create_all()` en ningún punto. El
   esquema lo crean migraciones SQL numeradas que se aplican con scripts
   explícitos, y la idempotencia no sustituye al versionado.
3. **Las credenciales llegan por archivo**, montado como Compose secret, nunca
   como variable de entorno con su valor. Ninguna API carga el `.env` del
   proyecto, que contiene la clave de unseal y el token inicial de Vault.
