# vpgcontafiscal_automatizacion
Automatizacion Inteligente para contabilidad fiscal VPG

## Componente 1: HashiCorp Vault (credenciales del crawler)

Vault 2.1.1 en modo servidor (no dev), almacenamiento integrado Raft en un
volumen Docker y motor de secretos KV v2. El puerto 8200 se publica solo en
`127.0.0.1`.

| Archivo | Propósito |
|---|---|
| `Dockerfile` | Multistage: `vault-assets` (normaliza CRLF y permisos) → `vault-server` |
| `compose.yaml` | Servicio `vault-service`, red `network-service`, volumen persistente |
| `config/vault.hcl` | Configuración del servidor |
| `docker-entrypoint.sh` | Ejecuta `vault server` con la configuración del proyecto |
| `.env.example` | Parámetros no sensibles `VAULT_*` (copiar a `.env`) |
| `requirements/vault.txt` | Sin dependencias Python |

### Requisitos previos

- Windows con Docker Desktop (backend WSL 2) en ejecución.
- Git for Windows (Git Bash).
- Comprobar: `docker version` y `docker compose version`.

> **Git Bash:** si un comando interactivo muestra `the input device is not a TTY`,
> antepón `winpty` (p. ej. `winpty docker compose exec vault-service vault operator unseal`).
> Los argumentos que empiezan con `/` se convierten en rutas de Windows; por eso
> esos comandos llevan `MSYS_NO_PATHCONV=1`.

### 1. Preparar y construir

```bash
cp .env.example .env          # solo parámetros no sensibles
docker compose config         # valida la configuración resultante
docker compose build
```

### 2. Iniciar y consultar estado

```bash
docker compose up -d
docker compose ps
docker compose exec vault-service vault status   # Sealed: true hasta desbloquear
```

`vault status` devuelve código 2 mientras esté sellado; es normal.

### 3. Inicializar (solo una vez por volumen)

```bash
docker compose exec vault-service vault operator init -key-shares=1 -key-threshold=1
```

La salida muestra la **Unseal Key** y el **Initial Root Token** una sola vez.
Guárdalos de inmediato en un gestor de contraseñas y limpia la pantalla (`clear`).
No los redirijas a archivos del proyecto ni los pegues en comandos.
Para un esquema más robusto usa, por ejemplo, `-key-shares=3 -key-threshold=2`
y reparte las claves.

### 4. Desbloquear e iniciar sesión

Los comandos piden el valor de forma oculta; nada queda en el historial.

```bash
docker compose exec vault-service vault operator unseal   # pega la Unseal Key
docker compose exec vault-service vault login -no-print   # pega el token
```

El token queda en `~/.vault-token` **dentro del contenedor** (no en el proyecto
ni en el volumen) y se pierde si el contenedor se recrea.

### 5. Habilitar KV v2 (solo una vez)

```bash
docker compose exec vault-service vault secrets enable -path=secret -version=2 kv
docker compose exec vault-service vault secrets list
```

### 6. Guardar credenciales de ejemplo

Valores de ejemplo: usuario `__Fulanito__`, password `__MyS3cret0__`; sustitúyelos
por los reales. La contraseña se lee oculta y se envía por stdin (`password=-`),
así no aparece en el historial ni en los argumentos del comando.

```bash
read -rsp 'Password: ' VPG_PASS; echo
printf '%s' "$VPG_PASS" | docker compose exec -T vault-service \
  vault kv put -mount=secret crawler/ejemplo usuario=__Fulanito__ password=-
unset VPG_PASS
```

### 7. Recuperar cada valor

```bash
docker compose exec vault-service vault kv get -mount=secret -field=usuario crawler/ejemplo
docker compose exec vault-service vault kv get -mount=secret -field=password crawler/ejemplo
docker compose exec vault-service vault kv metadata get -mount=secret crawler/ejemplo   # versiones
```

### 8. Logs, reinicio y parada

```bash
docker compose logs -f vault-service       # Ctrl+C para salir
docker compose restart vault-service       # reinicia el mismo contenedor
docker compose stop                        # detiene sin borrar nada
docker compose down                        # elimina contenedor y red; conserva el volumen
```

**Nunca** uses `docker compose down -v` salvo que quieras borrar todos los
secretos: elimina el volumen `vpg-vault-data`.

Para cerrar la sesión en el contenedor al terminar:

```bash
MSYS_NO_PATHCONV=1 docker compose exec vault-service rm -f /home/vault/.vault-token
```

### Qué se repite tras reiniciar

| Evento | Desbloquear (unseal) | Iniciar sesión (login) | Init / habilitar KV |
|---|---|---|---|
| `restart`, `stop`/`start`, reinicio de Docker Desktop o Windows | Sí | No (el token sigue en el contenedor) | No |
| `down` + `up -d` o `build` + `up -d` (contenedor recreado) | Sí | Sí | No |
| `down -v` (volumen borrado) | — | — | Sí, todo desde el paso 3 |

Vault siempre arranca sellado: el desbloqueo es manual a propósito; no se
guardan claves en el proyecto para automatizarlo.

### Verificar que el volumen conserva los secretos

```bash
docker volume inspect vpg-vault-data
docker compose down
docker compose up -d
docker compose exec vault-service vault operator unseal
docker compose exec vault-service vault login -no-print
docker compose exec vault-service vault kv get -mount=secret -field=usuario crawler/ejemplo
MSYS_NO_PATHCONV=1 docker compose exec vault-service ls -la /vault/data
```

Si el valor aparece tras recrear el contenedor, el volumen persiste los datos.

### Interfaz web

<http://127.0.0.1:8200/ui> (solo accesible desde este equipo).

### Notas de seguridad

- `tls_disable = true` solo es aceptable porque el puerto se publica en
  `127.0.0.1`. Para cualquier despliegue compartido habilita TLS.
- `disable_mlock = true` es lo recomendado con Raft; implica que la memoria de
  Vault podría ir a swap. En WSL 2 el swap vive en un archivo del host; si te
  preocupa, desactívalo en `.wslconfig` (`swap=0`).
- Revisa vulnerabilidades de la imagen construida con
  `docker scout cves vpg/vault-server:2.1.1`.
