"""Logs en JSON con X-Request-ID.

Que se registra: identificador de peticion, actor, UUID objetivo, operacion,
estado y duracion.

Que NO se registra, nunca: cuerpos de login o de enrolamiento, cabecera
``Authorization``, tokens, contrasenas, codigos TOTP, URIs ``otpauth://``,
codigos QR ni valores de secretos. Las rutas sensibles estan en
``_NO_BODY_PATHS`` y el formateador ademas filtra por patron, por si algo se
cuela desde un proveedor externo.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import uuid
from typing import Any

# Campos que jamas deben salir en un log, vengan de donde vengan.
_FORBIDDEN_KEYS = frozenset(
    {
        "password", "passcode", "totp", "totp_code", "code", "secret", "secret_id",
        "role_id", "token", "client_token", "vault_token", "authorization",
        "x-vault-token", "url", "otpauth", "qr", "seed", "mfa_request_id",
        "session_id", "api_session", "new_password", "current_password",
    }
)

_REDACT_PATTERNS = (
    re.compile(r"\bhv[sb]\.[A-Za-z0-9_\-\.]+"),
    re.compile(r"otpauth://[^\s\"']+", re.IGNORECASE),
    re.compile(r"\b\d{6}\b(?=\s*(?:totp|passcode|codigo))", re.IGNORECASE),
)

REQUEST_ID_HEADER = "X-Request-ID"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def validate_request_id(raw: str | None) -> str:
    """Acepta el X-Request-ID del cliente solo si tiene forma razonable.

    Un identificador arbitrario del cliente acaba en los logs: se valida para
    que no pueda inyectar saltos de linea ni cargas enormes.
    """
    if raw and _REQUEST_ID_RE.match(raw):
        return raw
    return uuid.uuid4().hex


def scrub(value: Any, *, _depth: int = 0) -> Any:
    """Elimina de una estructura cualquier clave o patron sensible."""
    if _depth > 6:
        return "[PROFUNDIDAD_MAXIMA]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in _FORBIDDEN_KEYS:
                out[str(key)] = "[REDACTADO]"
            else:
                out[str(key)] = scrub(item, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [scrub(v, _depth=_depth + 1) for v in value]
    if isinstance(value, str):
        text = value
        for pattern in _REDACT_PATTERNS:
            text = pattern.sub("[REDACTADO]", text)
        return text
    return value


class JsonFormatter(logging.Formatter):
    _STANDARD = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": scrub(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key in self._STANDARD or key.startswith("_"):
                continue
            # La clave tambien se comprueba, no solo el valor: un extra llamado
            # 'password' no se salva por ser una cadena sin patron reconocible.
            if key.lower() in _FORBIDDEN_KEYS:
                payload[key] = "[REDACTADO]"
            else:
                payload[key] = scrub(value)
        if record.exc_info:
            # Solo el tipo y el mensaje saneado: la traza completa puede
            # arrastrar valores de variables locales.
            exc_type, exc_value, _ = record.exc_info
            payload["error_type"] = getattr(exc_type, "__name__", "Exception")
            payload["error"] = scrub(str(exc_value))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True
    # El access log de uvicorn incluiria rutas con UUID; el middleware propio ya
    # registra lo necesario y sin datos personales.
    logging.getLogger("uvicorn.access").disabled = True
    # SQLAlchemy en INFO imprimiria las sentencias y sus parametros.
    logging.getLogger("sqlalchemy.engine").setLevel("WARNING")
    # httpx registra cada peticion con su URL completa: ruido, y ademas podria
    # incluir una ruta de secreto. El middleware ya deja constancia de lo util.
    logging.getLogger("httpx").setLevel("WARNING")
    logging.getLogger("httpcore").setLevel("WARNING")


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
