"""Quien es el receptor que llama al canal interno de aprovisionamiento.

El contrato es deliberadamente pequeno: una credencial aleatoria **por
receptor**, generada en local por el Makefile, guardada en ``secrets/`` y
montada solo en los componentes que participan. El servidor asocia esa
credencial con el receptor, y el receptor con su consumidor.

Tres decisiones que conviene justificar, porque son las que sostienen el resto:

* **``consumer_id`` no es una contrasena.** Es un identificador que aparece en
  respuestas administrativas, en la auditoria y en los logs de operacion.
  Aceptarlo como prueba de identidad convertiria un dato de inventario en una
  llave. Por eso el claim no lo acepta: se resuelve desde la credencial.
* **Comparacion en tiempo constante.** Se comparan todas las credenciales
  configuradas con ``compare_digest`` y se acumula la coincidencia, sin cortar
  en la primera: un cortocircuito filtraria por tiempo cuantos receptores hay y
  cual coincidio parcialmente.
* **La credencial no se registra nunca.** Ni completa, ni truncada, ni como
  hash. Lo que entra en el log es el nombre del receptor ya resuelto; en un
  fallo, ni eso, porque no se sabe quien llamaba.

Lo que esta credencial **no** hace: no cifra el transporte. En esta prueba local
el canal es HTTP dentro de la red de Docker. La credencial autentica a quien
llama; para proteger el transito haria falta TLS, y aqui no se usa.
"""

from __future__ import annotations

import secrets

from app.core.errors import UnauthenticatedError
from app.core.logging import get_logger
from app.vault_mgmt.core.config import Settings

logger = get_logger(__name__)


class ReceiverRegistry:
    """Credenciales de los receptores configurados, resueltas al arrancar."""

    def __init__(self, settings: Settings) -> None:
        self._header = settings.receiver_credential_header
        self._declared = settings.configured_receivers
        self._credentials = dict(settings.receiver_credentials)
        faltan = [name for name in self._declared if name not in self._credentials]
        if faltan:
            # Declarado sin archivo = no puede reclamar. Se dice una vez al
            # arrancar; no se inventa una credencial vacia.
            logger.warning(
                "receptores declarados sin archivo de credencial legible: no "
                "podran reclamar emisiones",
                extra={"operation": "receiver_auth", "receivers": ",".join(faltan)},
            )

    @property
    def header(self) -> str:
        return self._header

    @property
    def configured(self) -> tuple[str, ...]:
        """Receptores que de verdad tienen credencial cargada."""
        return tuple(sorted(self._credentials))

    @property
    def declared(self) -> tuple[str, ...]:
        return self._declared

    @property
    def usable(self) -> bool:
        return bool(self._credentials)

    def identify(self, presented: str | None) -> str:
        """Devuelve el receptor al que pertenece la credencial presentada.

        Un fallo es 401 y el mensaje no distingue "credencial desconocida" de
        "receptor sin configurar": decirlo seria confirmar nombres validos a
        quien no tiene ninguno.
        """
        if not presented:
            raise UnauthenticatedError(
                f"falta la cabecera {self._header} con la credencial del "
                "receptor. La genera 'make all' en secrets/ y se monta en el "
                "receptor; no es el consumer_id.",
                code="receiver_credential_missing",
            )

        encontrado = ""
        for name, secret in self._credentials.items():
            # Sin cortocircuito: se comparan todas y se acumula el resultado.
            if secrets.compare_digest(presented, secret.get_secret_value()):
                encontrado = name
        if not encontrado:
            raise UnauthenticatedError(
                "la credencial del receptor no es valida",
                code="receiver_credential_invalid",
            )
        return encontrado


__all__ = ["ReceiverRegistry"]
