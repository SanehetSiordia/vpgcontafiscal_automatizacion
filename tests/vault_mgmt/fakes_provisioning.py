"""Doble del administrador de AppRole para la etapa 4.6.

Vive en su propio modulo y no en ``conftest.py`` porque es la pieza mas larga de
los dobles y tiene comportamiento propio que conviene poder leer de una vez.

Que reproduce, y por que esas cosas y no otras
----------------------------------------------
Lo que importa del aprovisionamiento no es "llamar a Vault", es el
comportamiento del que dependen las garantias que la etapa promete:

* El SecretID **no sale en claro**. Se devuelve envuelto y la envoltura es de
  **un solo uso**: ``unwrap`` la consume y un segundo intento falla. Asi una
  prueba puede comprobar que el servicio nunca ve el valor.
* Un SecretID se destruye por su **accessor**, y destruirlo **no** revoca los
  tokens que ya salieron de el. Las dos cosas se pueden comprobar aqui, que es
  justo la confusion que la documentacion advierte.
* La **guarda de alcance** es real: un rol que no empieza por el prefijo
  gestionado levanta ``ValueError``, igual que el cliente de verdad. Si el doble
  fuera permisivo, la prueba de que no se toca un rol ajeno no probaria nada.
* ``login`` exige que ``role_id`` y ``secret_id`` correspondan, y marca en los
  metadatos del token el accessor del SecretID consumido, como hace Vault.
Lo que este doble NO puede comprobar, y conviene tenerlo presente: **el formato
de hilo contra Vault**. Sustituye al cliente entero, asi que un fallo del propio
cliente (por ejemplo, enviar ``metadata`` como objeto cuando Vault exige una
cadena JSON) pasaria por aqui sin que nadie se enterase. Eso ocurrio: la suite
iba en verde y el recorrido contra Vault real respondia 503. Ese limite tiene su
propia prueba, contra el cliente de verdad y un transporte HTTP falso, en
``test_approle_admin_wire.py``.

Lo que **no** demuestra, y queda como comprobacion manual documentada en el
README: el comportamiento exacto de Vault al envolver, los TTL reales, y el
efecto de las politicas HCL. Un doble no valida a Vault.
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any


class FakeAppRole:
    """Doble de ``app.vault_mgmt.core.approle_admin.AppRoleAdminClient``."""

    def __init__(self, settings: Any, probe: Any) -> None:
        self._settings = settings
        self._probe = probe
        self.mount = settings.managed_approle_mount
        # rol -> role_id
        self.roles: dict[str, str] = {}
        # accessor -> {role, secret_id, metadata, alive}
        self.secret_ids: dict[str, dict[str, Any]] = {}
        # wrap token -> {secret_id, accessor, role, expires_at, used}
        self.wraps: dict[str, dict[str, Any]] = {}
        self.policy_written = 0
        self.mount_enabled = False
        self.destroyed: list[str] = []
        self.revoked_tokens: list[str] = []
        # Permite que una prueba fuerce un fallo de Vault en la siguiente emision.
        self.fail_next_issue: BaseException | None = None
        self.available = True

    # -- guarda de alcance, igual que en el cliente real ---------------------

    def _check(self, role_name: str) -> None:
        prefix = self._settings.managed_role_prefix
        if not role_name.startswith(prefix):
            raise ValueError(
                f"'{role_name}' no es un rol gestionado por esta API "
                f"(deberia empezar por '{prefix}'): no se toca"
            )

    async def aclose(self) -> None:
        return None

    # -- montaje, politica y rol --------------------------------------------

    async def ensure_mount(self) -> bool:
        self.mount_enabled = True
        return True

    async def ensure_policy(self) -> None:
        self.policy_written += 1

    def managed_policy_hcl(self) -> str:
        # Sin lectura de KV: es lo que hace que "entrega mediada" signifique algo.
        return 'path "sys/wrapping/unwrap" { capabilities = ["update"] }'

    async def ensure_role(self, role_name: str) -> None:
        self._check(role_name)
        self.roles.setdefault(role_name, f"role-{uuid.uuid4().hex[:12]}")

    async def role_exists(self, role_name: str) -> bool:
        self._check(role_name)
        return role_name in self.roles

    async def read_role(self, role_name: str) -> Any:
        self._check(role_name)
        if role_name not in self.roles:
            return None
        from app.vault_mgmt.core.approle_admin import RoleInfo

        return RoleInfo(
            role_id=self.roles[role_name],
            policies=(self._settings.managed_policy_name,),
            token_ttl_seconds=self._settings.crawler_token_ttl_seconds,
        )

    async def delete_role(self, role_name: str) -> None:
        self._check(role_name)
        self.roles.pop(role_name, None)

    # -- SecretID ------------------------------------------------------------

    async def issue_wrapped_secret_id(
        self, role_name: str, *, metadata: Any, wrap_ttl_seconds: int
    ) -> Any:
        self._check(role_name)
        # Llega el MISMO dict que recibe el cliente real desde el servicio. La
        # serializacion a cadena JSON que exige Vault es cosa del cliente, no
        # del servicio, asi que este doble no puede comprobarla: sustituye al
        # cliente entero. Ese limite es real y tiene su propia prueba, contra el
        # cliente de verdad y un transporte HTTP falso
        # (test_approle_admin_wire.py). Un doble no valida a quien reemplaza.
        if not isinstance(metadata, dict):
            raise AssertionError(
                "el servicio deberia pasar los metadatos como dict; "
                f"llego {type(metadata).__name__}"
            )
        if self.fail_next_issue is not None:
            exc = self.fail_next_issue
            self.fail_next_issue = None
            raise exc
        from app.vault_mgmt.core.approle_admin import WrappedSecretId

        accessor = f"sid-{uuid.uuid4().hex[:10]}"
        secret_id = f"secret-{uuid.uuid4().hex}"
        wrap_token = f"wrap-{uuid.uuid4().hex}"
        # Vault devuelve en wrap_info el accessor del WRAPPING TOKEN. El del
        # SecretID viaja DENTRO de la envoltura, asi que el servicio no lo ve
        # hasta que el receptor entra y lo acredita en el ack. Reproducirlo es
        # importante: si el doble devolviera el del SecretID, la reconciliacion
        # parecerian funcionar por un camino que en Vault no existe.
        wrap_accessor = f"wrapacc-{uuid.uuid4().hex[:10]}"
        self.secret_ids[accessor] = {
            "role": role_name,
            "secret_id": secret_id,
            "metadata": dict(metadata),
            "alive": True,
        }
        expires = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=wrap_ttl_seconds)
        self.wraps[wrap_token] = {
            "secret_id": secret_id,
            "accessor": accessor,
            "role": role_name,
            "expires_at": expires,
            "used": False,
        }
        return WrappedSecretId(
            token=wrap_token,
            accessor=wrap_accessor,
            ttl_seconds=wrap_ttl_seconds,
            expires_at=expires,
        )

    async def lookup_secret_id_accessor(
        self, role_name: str, accessor: str
    ) -> dict[str, Any] | None:
        """Como Vault: devuelve los metadatos bajo ``metadata``.

        Es por esos metadatos (que llevan el ``delivery_id``) por donde la
        reconciliacion identifica un SecretID huerfano, asi que el doble tiene
        que exponerlos con la misma forma.
        """
        self._check(role_name)
        data = self.secret_ids.get(accessor)
        if not data or not data["alive"]:
            return None
        return {"metadata": dict(data["metadata"]), "secret_id_accessor": accessor}

    async def destroy_secret_id_accessor(self, role_name: str, accessor: str) -> bool:
        self._check(role_name)
        data = self.secret_ids.get(accessor)
        if not data or not data["alive"]:
            return False
        data["alive"] = False
        self.destroyed.append(accessor)
        return True

    async def list_secret_id_accessors(self, role_name: str) -> list[str]:
        self._check(role_name)
        return [
            accessor
            for accessor, data in self.secret_ids.items()
            if data["role"] == role_name and data["alive"]
        ]

    # -- tokens --------------------------------------------------------------

    async def revoke_token_accessor(self, accessor: str) -> bool:
        """Revoca de verdad: el token deja de existir, como en Vault.

        Si solo lo apuntara en una lista, una prueba no podria distinguir
        "revocado" de "se intento revocar", que es justo la diferencia que
        importa en una rotacion.
        """
        self.revoked_tokens.append(accessor)
        muertos = [t for t, d in self._probe.tokens.items() if d.get("accessor") == accessor]
        for token in muertos:
            del self._probe.tokens[token]
        return bool(muertos)

    async def lookup_token(self, token: str) -> dict[str, Any]:
        """``lookup`` de un token ajeno. Comparte registro con ``FakeProbe``."""
        data = self._probe.tokens.get(token)
        return dict(data) if data else {}

    # -- lo que haria el RECEPTOR, para las pruebas --------------------------

    def unwrap(self, wrap_token: str) -> str:
        """Desenvuelve la entrega. UN SOLO USO, y caduca."""
        data = self.wraps.get(wrap_token)
        if data is None:
            raise AssertionError("ese wrapping token no existe")
        if data["used"]:
            raise AssertionError("un wrapping token es de un solo uso")
        if data["expires_at"] <= dt.datetime.now(dt.UTC):
            raise AssertionError("ese wrapping token ya caduco")
        data["used"] = True
        return str(data["secret_id"])

    def expire_wrap(self, wrap_token: str) -> None:
        """Adelanta la caducidad de una envoltura, sin esperar su TTL."""
        self.wraps[wrap_token]["expires_at"] = dt.datetime.now(dt.UTC) - dt.timedelta(
            seconds=1
        )

    def login(self, role_id: str, secret_id: str, *, ttl: int = 1200) -> str:
        """Canjea ``role_id`` + ``secret_id`` por un token, como approle/login."""
        for accessor, data in self.secret_ids.items():
            if data["secret_id"] != secret_id:
                continue
            if not data["alive"]:
                raise AssertionError("ese secret_id ya se destruyo")
            role = data["role"]
            if self.roles.get(role) != role_id:
                raise AssertionError("el role_id no corresponde a ese secret_id")
            token = f"machine-{uuid.uuid4().hex}"
            self._probe.register_machine(
                token,
                mount=self.mount,
                role_name=role,
                policies=(self._settings.managed_policy_name,),
                ttl=ttl,
            )
            # Vault copia en los metadatos del token los del SecretID que se
            # canjeo (consumer_id, delivery_id, operation_id, receiver) y anade
            # role_name. Lo que NO incluye es el accessor del SecretID: se
            # comprobo contra Vault real. El ack usa el delivery_id de aqui para
            # verificar que el token viene de ESA entrega.
            self._probe.tokens[token]["meta"].update(data["metadata"])
            # secret_id_num_uses=1: el SecretID queda consumido en este login.
            if self._settings.crawler_secret_id_num_uses == 1:
                data["alive"] = False
            return token
        raise AssertionError("ningun secret_id coincide")

    def issue_foreign_token(self, *, role_name: str, policies: tuple[str, ...]) -> str:
        """Token VALIDO en Vault pero de otra identidad.

        Es el caso que el ``ack`` debe rechazar: la credencial existe, el lookup
        pasa, y aun asi no es quien el catalogo espera para ese consumidor.
        """
        token = f"foreign-{uuid.uuid4().hex}"
        self._probe.register_machine(
            token, mount=self.mount, role_name=role_name, policies=policies
        )
        return token


__all__ = ["FakeAppRole"]
