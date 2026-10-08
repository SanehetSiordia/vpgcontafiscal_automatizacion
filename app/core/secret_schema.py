"""Esquema tipado de una coleccion: definicion, documento JSON Schema y validacion.

Modulo compartido por los dos servicios. ``vault-mgmt-service`` lo usa para
definir y publicar esquemas; ``user-mgmt-service`` lo usa en su pasarela interna
para **volver a validar** el objeto completo antes de escribir en Vault: la
pasarela es la frontera de autorizacion y no da por buena la validacion que diga
el llamante.

Tres piezas:

1. ``normalize_fields``   valida la **definicion** de campos que envia un
   administrador y la deja en forma canonica.
2. ``build_json_schema``  genera el documento **JSON Schema (Draft 2020-12)**
   equivalente. Ese documento se guarda junto a la version del esquema, de modo
   que una version historica conserva exactamente el documento que la valido.
3. ``validate_values``    valida un objeto de valores contra ese documento.

Por que un validador propio y no la libreria ``jsonschema``
-----------------------------------------------------------
El enunciado pide validacion de esquema JSON **sin referencias externas ni
ejecucion de codigo**. El subconjunto que este servicio emite es cerrado y
conocido (``type``, ``enum``, ``required``, ``properties``,
``additionalProperties: false``, ``items``, ``minItems``/``maxItems``,
``minLength``/``maxLength``, ``minimum``/``maximum``), de modo que validarlo son
unas decenas de lineas deterministas, sin ``$ref``, sin ``$dynamicRef``, sin
resolucion de URI y sin ``format`` como asercion.

Lo que se gana: ninguna dependencia nativa nueva. ``jsonschema`` arrastra
``rpds-py``, que es una extension compilada en Rust; en ``python:3.12-alpine``
(musl) eso significa, o una rueda musllinux que puede no existir para una
version futura, o meter la cadena de compilacion de Rust en la etapa builder.
El proyecto ya pago ese peaje con ``psycopg`` y esta documentado en
``requirements/user_mgmt.txt``.

Lo que se pierde, dicho sin adornos: este validador cubre **solo** el
subconjunto que se genera aqui, no JSON Schema completo. Para compensarlo, el
documento guardado en ``secret_collection_schemas.json_schema`` es JSON Schema
estandar y lo publica ``GET .../schema``: cualquier validador externo puede
comprobar los mismos valores y debe llegar al mismo veredicto.

Lo que la clasificacion ``sensitive`` SI y NO hace
--------------------------------------------------
Controla presentacion y registro: un campo sensible no se nombra en mensajes de
error con su valor, ni aparece en logs. **No** convierte el valor en seguro: el
valor sigue siendo un secreto y la proteccion real la dan Vault (almacenamiento)
y los permisos de entrega.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Literal

FieldType = Literal[
    "string", "number", "integer", "boolean", "object", "array", "file_reference"
]

FIELD_TYPES: tuple[str, ...] = (
    "string",
    "number",
    "integer",
    "boolean",
    "object",
    "array",
    "file_reference",
)

# Tipos admitidos como elemento de un array o como propiedad de un object
# anidado. No se admite 'array' de 'array': la profundidad se controla aparte y
# un anidamiento asi no aporta nada a un registro de credenciales.
NESTED_TYPES: tuple[str, ...] = (
    "string",
    "number",
    "integer",
    "boolean",
    "object",
    "file_reference",
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

# Esquemas de URI admitidos en un file_reference. Allowlist cerrada: el campo
# es una REFERENCIA a un archivo externo, no su contenido.
FILE_REFERENCE_SCHEMES: tuple[str, ...] = ("file://", "s3://", "https://", "gs://")

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"


class SchemaDefinitionError(ValueError):
    """La definicion de campos no es valida. Se traduce a 422."""


@dataclass(slots=True, frozen=True)
class ValueProblem:
    """Un fallo de validacion. ``field`` es la ruta; nunca lleva el valor."""

    field: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "reason": self.reason}


class ValuesInvalid(ValueError):
    """Los valores no superan el esquema. Lleva la lista de problemas."""

    def __init__(self, problems: list[ValueProblem]) -> None:
        super().__init__("los valores no superan el esquema de la coleccion")
        self.problems = problems


# ---------------------------------------------------------------------------
# 1. Definicion de campos
# ---------------------------------------------------------------------------


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SchemaDefinitionError(message)


def _int_or(raw: dict[str, Any], key: str, default: int, *, where: str) -> int:
    """Lee un entero distinguiendo AUSENTE de cero.

    ``int(raw.get(key) or default)`` parece razonable y no lo es: ``0`` es
    falsy, asi que un ``max_length: 0`` se convertiria en silencio en el tope
    por defecto en vez de rechazarse. Aqui solo la ausencia (o ``null``) usa el
    valor por omision; un cero enviado a proposito llega a la comprobacion de
    rango y se rechaza alli.
    """
    value = raw.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise SchemaDefinitionError(f"{where}: '{key}' debe ser un entero")
    return value


def _normalize_one(
    raw: dict[str, Any],
    *,
    depth: int,
    limits: Limits,
    path: str,
) -> dict[str, Any]:
    _require(isinstance(raw, dict), f"{path}: cada campo debe ser un objeto")

    name = str(raw.get("name") or "").strip()
    _require(bool(name), f"{path}: falta 'name'")
    _require(
        len(name) <= limits.max_field_name_length,
        f"{path}.{name}: el nombre excede {limits.max_field_name_length} caracteres",
    )
    _require(
        _NAME_RE.match(name) is not None,
        f"{path}.{name}: el nombre debe ser minusculas, digitos y '_', empezando por letra",
    )

    field_type = str(raw.get("type") or "").strip()
    allowed = FIELD_TYPES if depth == 0 else NESTED_TYPES
    _require(
        field_type in allowed,
        f"{path}.{name}: tipo '{field_type}' no admitido aqui (admitidos: {', '.join(allowed)})",
    )

    field: dict[str, Any] = {
        "name": name,
        "type": field_type,
        "required": bool(raw.get("required", False)),
        "sensitive": bool(raw.get("sensitive", False)),
    }
    description = raw.get("description")
    if description is not None:
        text = str(description).strip()
        _require(len(text) <= 400, f"{path}.{name}: 'description' excede 400 caracteres")
        if text:
            field["description"] = text

    if field_type == "string":
        max_length = _int_or(
            raw, "max_length", limits.max_string_value_length, where=f"{path}.{name}"
        )
        _require(
            1 <= max_length <= limits.max_string_value_length,
            f"{path}.{name}: 'max_length' debe estar entre 1 y {limits.max_string_value_length}",
        )
        min_length = _int_or(raw, "min_length", 0, where=f"{path}.{name}")
        _require(
            0 <= min_length <= max_length,
            f"{path}.{name}: 'min_length' no puede superar 'max_length'",
        )
        field["max_length"] = max_length
        if min_length:
            field["min_length"] = min_length
        enum = raw.get("enum")
        if enum is not None:
            _require(
                isinstance(enum, list) and 1 <= len(enum) <= 50,
                f"{path}.{name}: 'enum' debe ser una lista de 1 a 50 valores",
            )
            _require(
                all(isinstance(item, str) for item in enum),
                f"{path}.{name}: 'enum' de un string solo admite cadenas",
            )
            field["enum"] = list(enum)

    elif field_type in ("number", "integer"):
        minimum = raw.get("minimum")
        maximum = raw.get("maximum")
        if minimum is not None:
            _require(
                isinstance(minimum, (int, float)) and not isinstance(minimum, bool),
                f"{path}.{name}: 'minimum' debe ser numerico",
            )
            field["minimum"] = minimum
        if maximum is not None:
            _require(
                isinstance(maximum, (int, float)) and not isinstance(maximum, bool),
                f"{path}.{name}: 'maximum' debe ser numerico",
            )
            field["maximum"] = maximum
        if minimum is not None and maximum is not None:
            _require(
                minimum <= maximum,
                f"{path}.{name}: 'minimum' no puede superar 'maximum'",
            )

    elif field_type == "array":
        items_type = str(raw.get("items_type") or "string")
        _require(
            items_type in NESTED_TYPES,
            f"{path}.{name}: 'items_type' no admitido: {items_type}",
        )
        max_items = _int_or(
            raw, "max_items", limits.max_array_items, where=f"{path}.{name}"
        )
        _require(
            1 <= max_items <= limits.max_array_items,
            f"{path}.{name}: 'max_items' debe estar entre 1 y {limits.max_array_items}",
        )
        field["items_type"] = items_type
        field["max_items"] = max_items
        if items_type == "object":
            _require(
                depth + 1 < limits.max_object_depth,
                f"{path}.{name}: se excede la profundidad maxima ({limits.max_object_depth})",
            )
            field["properties"] = _normalize_many(
                raw.get("properties") or [],
                depth=depth + 1,
                limits=limits,
                path=f"{path}.{name}[]",
            )
        elif items_type == "string":
            field["max_length"] = _int_or(
                raw,
                "max_length",
                limits.max_string_value_length,
                where=f"{path}.{name}",
            )
            _require(
                1 <= field["max_length"] <= limits.max_string_value_length,
                f"{path}.{name}: 'max_length' fuera de rango",
            )

    elif field_type == "object":
        _require(
            depth + 1 < limits.max_object_depth,
            f"{path}.{name}: se excede la profundidad maxima ({limits.max_object_depth})",
        )
        field["properties"] = _normalize_many(
            raw.get("properties") or [],
            depth=depth + 1,
            limits=limits,
            path=f"{path}.{name}",
        )

    # file_reference y boolean no llevan parametros propios.
    return field


def _normalize_many(
    raw_fields: Any, *, depth: int, limits: Limits, path: str
) -> list[dict[str, Any]]:
    _require(isinstance(raw_fields, list), f"{path}: 'properties' debe ser una lista")
    _require(
        len(raw_fields) <= limits.max_fields_per_schema,
        f"{path}: como maximo {limits.max_fields_per_schema} campos",
    )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw_fields:
        field = _normalize_one(item, depth=depth, limits=limits, path=path)
        _require(field["name"] not in seen, f"{path}: campo duplicado '{field['name']}'")
        seen.add(field["name"])
        out.append(field)
    return out


@dataclass(slots=True, frozen=True)
class Limits:
    """Topes de tamano que vienen de la configuracion del servicio."""

    max_fields_per_schema: int
    max_field_name_length: int
    max_string_value_length: int
    max_object_depth: int
    max_array_items: int
    max_record_bytes: int


def normalize_fields(raw_fields: Any, *, limits: Limits) -> list[dict[str, Any]]:
    """Valida y canoniza la definicion de campos. Lanza ``SchemaDefinitionError``."""
    fields = _normalize_many(raw_fields, depth=0, limits=limits, path="fields")
    _require(bool(fields), "el esquema necesita al menos un campo")
    return fields


# ---------------------------------------------------------------------------
# 2. Documento JSON Schema
# ---------------------------------------------------------------------------


def _node_for(field: dict[str, Any]) -> dict[str, Any]:
    kind = field["type"]
    node: dict[str, Any] = {}
    if description := field.get("description"):
        node["description"] = description

    if kind == "string":
        node["type"] = "string"
        node["maxLength"] = field["max_length"]
        if field.get("min_length"):
            node["minLength"] = field["min_length"]
        if field.get("enum"):
            node["enum"] = list(field["enum"])

    elif kind == "integer":
        node["type"] = "integer"
        if "minimum" in field:
            node["minimum"] = field["minimum"]
        if "maximum" in field:
            node["maximum"] = field["maximum"]

    elif kind == "number":
        node["type"] = "number"
        if "minimum" in field:
            node["minimum"] = field["minimum"]
        if "maximum" in field:
            node["maximum"] = field["maximum"]

    elif kind == "boolean":
        node["type"] = "boolean"

    elif kind == "object":
        node.update(_object_node(field.get("properties") or []))

    elif kind == "array":
        node["type"] = "array"
        node["maxItems"] = field["max_items"]
        items_type = field["items_type"]
        if items_type == "object":
            node["items"] = _object_node(field.get("properties") or [])
        elif items_type == "string":
            node["items"] = {"type": "string", "maxLength": field["max_length"]}
        elif items_type == "file_reference":
            node["items"] = _file_reference_node()
        else:
            node["items"] = {"type": items_type}

    elif kind == "file_reference":
        node.update(_file_reference_node())

    return node


def _object_node(fields: list[dict[str, Any]]) -> dict[str, Any]:
    required = [f["name"] for f in fields if f.get("required")]
    node: dict[str, Any] = {
        "type": "object",
        "properties": {f["name"]: _node_for(f) for f in fields},
        # Cerrado a proposito: un campo que no esta en el esquema no entra. Es
        # lo que permite afirmar que el registro es una tupla conocida.
        "additionalProperties": False,
    }
    if required:
        node["required"] = required
    return node


def _file_reference_node() -> dict[str, Any]:
    """Referencia a un archivo EXTERNO. Nunca el contenido del archivo.

    ``digest_sha256`` es solo una comprobacion de integridad del archivo
    referenciado. SHA-256 es un hash, no cifrado: no sustituye al archivo ni a
    ninguna credencial.
    """
    return {
        "type": "object",
        "description": (
            "Referencia a un archivo externo. KV no guarda el contenido ni base64."
        ),
        "properties": {
            "uri": {
                "type": "string",
                "maxLength": 2048,
                "minLength": 5,
                "description": "URI con esquema de la allowlist: "
                + ", ".join(FILE_REFERENCE_SCHEMES),
            },
            "media_type": {"type": "string", "maxLength": 128},
            "digest_sha256": {"type": "string", "minLength": 64, "maxLength": 64},
            "size_bytes": {"type": "integer", "minimum": 0, "maximum": 1099511627776},
        },
        "required": ["uri"],
        "additionalProperties": False,
    }


def build_json_schema(
    fields: list[dict[str, Any]],
    *,
    collection_id: uuid.UUID,
    schema_version: int,
    logical_name: str,
) -> dict[str, Any]:
    """Documento Draft 2020-12 equivalente a la definicion de campos.

    Sin ``$ref`` ni ``$defs``: el documento es autocontenido y no resuelve
    ninguna URI al validar. El ``$id`` es un URN informativo, no una direccion
    que alguien vaya a descargar.
    """
    document = _object_node(fields)
    document["$schema"] = JSON_SCHEMA_DIALECT
    document["$id"] = (
        f"urn:vpg:vault-mgmt:collection:{collection_id}:schema:{schema_version}"
    )
    document["title"] = f"{logical_name} v{schema_version}"
    document["x-vpg-generated-at"] = dt.datetime.now(dt.UTC).isoformat()
    # Campos sensibles, declarados como anotacion. No cambia la validacion:
    # sirve para que un cliente sepa que no debe mostrar ni registrar el valor.
    sensitive = sorted(f["name"] for f in fields if f.get("sensitive"))
    if sensitive:
        document["x-vpg-sensitive-fields"] = sensitive
    return document


def sensitive_field_names(fields: list[dict[str, Any]]) -> frozenset[str]:
    return frozenset(f["name"] for f in fields if f.get("sensitive"))


# ---------------------------------------------------------------------------
# 3. Validacion de valores
# ---------------------------------------------------------------------------


def _check_node(
    value: Any, node: dict[str, Any], path: str, problems: list[ValueProblem]
) -> None:
    expected = node.get("type")

    if expected == "object":
        if not isinstance(value, dict):
            problems.append(ValueProblem(path, "se esperaba un objeto"))
            return
        properties: dict[str, Any] = node.get("properties") or {}
        for name in node.get("required") or ():
            if name not in value:
                problems.append(ValueProblem(f"{path}.{name}", "campo obligatorio ausente"))
        if node.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    problems.append(
                        ValueProblem(
                            f"{path}.{name}",
                            "campo no declarado en el esquema de la coleccion",
                        )
                    )
        for name, child in properties.items():
            if name in value:
                _check_node(value[name], child, f"{path}.{name}", problems)
        return

    if expected == "array":
        if not isinstance(value, list):
            problems.append(ValueProblem(path, "se esperaba una lista"))
            return
        if "maxItems" in node and len(value) > node["maxItems"]:
            problems.append(
                ValueProblem(path, f"la lista excede {node['maxItems']} elementos")
            )
        if "minItems" in node and len(value) < node["minItems"]:
            problems.append(
                ValueProblem(path, f"la lista necesita al menos {node['minItems']} elementos")
            )
        item_node = node.get("items")
        if isinstance(item_node, dict):
            for index, item in enumerate(value[: node.get("maxItems", len(value))]):
                _check_node(item, item_node, f"{path}[{index}]", problems)
        return

    if expected == "string":
        if not isinstance(value, str):
            problems.append(ValueProblem(path, "se esperaba una cadena"))
            return
        if "maxLength" in node and len(value) > node["maxLength"]:
            problems.append(
                ValueProblem(path, f"excede la longitud maxima ({node['maxLength']})")
            )
        if "minLength" in node and len(value) < node["minLength"]:
            problems.append(
                ValueProblem(path, f"no alcanza la longitud minima ({node['minLength']})")
            )
        if "enum" in node and value not in node["enum"]:
            # Se nombran los valores ADMITIDOS (los declara el esquema, no son
            # secretos); nunca el valor enviado.
            problems.append(
                ValueProblem(path, f"valor fuera de la lista admitida: {node['enum']}")
            )
        return

    if expected == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(ValueProblem(path, "se esperaba un entero"))
            return
        _check_range(value, node, path, problems)
        return

    if expected == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            problems.append(ValueProblem(path, "se esperaba un numero"))
            return
        _check_range(value, node, path, problems)
        return

    if expected == "boolean":
        if not isinstance(value, bool):
            problems.append(ValueProblem(path, "se esperaba true o false"))
        return


def _check_range(
    value: float, node: dict[str, Any], path: str, problems: list[ValueProblem]
) -> None:
    if "minimum" in node and value < node["minimum"]:
        problems.append(ValueProblem(path, f"menor que el minimo ({node['minimum']})"))
    if "maximum" in node and value > node["maximum"]:
        problems.append(ValueProblem(path, f"mayor que el maximo ({node['maximum']})"))


def validate_values(
    values: Any,
    json_schema: dict[str, Any],
    *,
    fields: list[dict[str, Any]] | None = None,
    max_record_bytes: int | None = None,
) -> None:
    """Valida el objeto COMPLETO contra el documento. Lanza ``ValuesInvalid``.

    Se valida el resultado entero, tambien en un PATCH: media tupla valida no
    es una tupla valida.
    """
    problems: list[ValueProblem] = []
    if not isinstance(values, dict):
        raise ValuesInvalid([ValueProblem("values", "se esperaba un objeto de campos")])

    _check_node(values, json_schema, "values", problems)

    # Comprobaciones que no son del dialecto JSON Schema y se hacen aparte.
    if fields:
        _check_file_references(values, fields, "values", problems)

    if max_record_bytes is not None:
        try:
            size = len(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode())
        except (TypeError, ValueError):
            problems.append(ValueProblem("values", "el objeto no es JSON serializable"))
            size = 0
        if size > max_record_bytes:
            problems.append(
                ValueProblem(
                    "values",
                    f"el registro ocupa {size} bytes y el tope es {max_record_bytes}",
                )
            )

    if problems:
        raise ValuesInvalid(problems)


def _check_file_references(
    value: Any, fields: list[dict[str, Any]], path: str, problems: list[ValueProblem]
) -> None:
    """Allowlist de esquemas de URI. No se descarga ni se abre nada."""
    if not isinstance(value, dict):
        return
    for field in fields:
        name = field["name"]
        if name not in value:
            continue
        child = value[name]
        kind = field["type"]
        if kind == "file_reference":
            _check_one_reference(child, f"{path}.{name}", problems)
        elif kind == "object":
            _check_file_references(child, field.get("properties") or [], f"{path}.{name}", problems)
        elif kind == "array" and field.get("items_type") == "file_reference":
            if isinstance(child, list):
                for index, item in enumerate(child):
                    _check_one_reference(item, f"{path}.{name}[{index}]", problems)
        elif kind == "array" and field.get("items_type") == "object":
            if isinstance(child, list):
                for index, item in enumerate(child):
                    _check_file_references(
                        item, field.get("properties") or [], f"{path}.{name}[{index}]", problems
                    )


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _check_one_reference(value: Any, path: str, problems: list[ValueProblem]) -> None:
    if not isinstance(value, dict):
        return
    uri = value.get("uri")
    if isinstance(uri, str) and not uri.startswith(FILE_REFERENCE_SCHEMES):
        problems.append(
            ValueProblem(
                f"{path}.uri",
                "esquema de URI no admitido; permitidos: "
                + ", ".join(FILE_REFERENCE_SCHEMES),
            )
        )
    digest = value.get("digest_sha256")
    if isinstance(digest, str) and not _HEX64_RE.match(digest.lower()):
        problems.append(
            ValueProblem(f"{path}.digest_sha256", "debe ser SHA-256 en hexadecimal (64 digitos)")
        )


# ---------------------------------------------------------------------------
# 4. JSON Merge Patch (RFC 7386)
# ---------------------------------------------------------------------------


def apply_merge_patch(current: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """Aplica un JSON Merge Patch y devuelve el objeto resultante.

    Semantica exacta:
      * una clave ausente del patch **conserva** su valor;
      * ``null`` **elimina** la clave;
      * un objeto se mezcla de forma recursiva;
      * cualquier otro valor **sustituye** (una lista se reemplaza entera, no se
        concatena).

    No escribe nada: devuelve el objeto para validarlo COMPLETO antes de tocar
    Vault. Si el resultado no es valido, no hay escritura.
    """
    result = dict(current)
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = apply_merge_patch(result[key], value)
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# 5. Compatibilidad entre versiones de esquema
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class CompatibilityReport:
    """Resultado de comparar dos versiones de esquema.

    Se compara la DEFINICION, no los valores: diagnosticar compatibilidad
    leyendo todos los registros significaria leer todos los secretos, y el
    diagnostico nunca debe devolver valores.
    """

    compatible: bool
    breaking: list[ValueProblem]
    relaxing: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "compatible": self.compatible,
            "breaking_changes": [p.as_dict() for p in self.breaking],
            "safe_changes": list(self.relaxing),
        }


def _index(fields: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f["name"]: f for f in fields}


def check_compatibility(
    old_fields: list[dict[str, Any]], new_fields: list[dict[str, Any]], *, path: str = "fields"
) -> CompatibilityReport:
    """Compara dos definiciones y dice si la nueva acepta lo ya escrito.

    Rompe la compatibilidad:
      * quitar un campo (el objeto cerrado rechazaria los registros que lo tienen);
      * anadir un campo obligatorio (los registros existentes no lo traen);
      * cambiar el tipo de un campo;
      * volver obligatorio un campo que era opcional;
      * estrechar un limite (``max_length`` menor, rango mas estrecho,
        ``max_items`` menor, o un ``enum`` que pierde valores).

    No rompe: anadir un campo opcional, relajar un limite, dejar de exigir un
    campo o anadir valores a un ``enum``.
    """
    old = _index(old_fields)
    new = _index(new_fields)
    breaking: list[ValueProblem] = []
    relaxing: list[str] = []

    for name in old:
        if name not in new:
            breaking.append(
                ValueProblem(
                    f"{path}.{name}",
                    "el campo desaparece: los registros que lo tienen dejarian de validar",
                )
            )

    for name, field in new.items():
        where = f"{path}.{name}"
        previous = old.get(name)
        if previous is None:
            if field.get("required"):
                breaking.append(
                    ValueProblem(
                        where,
                        "campo nuevo obligatorio: los registros existentes no lo traen",
                    )
                )
            else:
                relaxing.append(f"{where}: campo opcional nuevo")
            continue

        if previous["type"] != field["type"]:
            breaking.append(
                ValueProblem(
                    where,
                    f"el tipo cambia de '{previous['type']}' a '{field['type']}'",
                )
            )
            continue

        if field.get("required") and not previous.get("required"):
            breaking.append(ValueProblem(where, "el campo pasa a ser obligatorio"))
        elif previous.get("required") and not field.get("required"):
            relaxing.append(f"{where}: deja de ser obligatorio")

        _compare_limits(previous, field, where, breaking, relaxing)

        if field["type"] == "object" or (
            field["type"] == "array" and field.get("items_type") == "object"
        ):
            nested = check_compatibility(
                previous.get("properties") or [],
                field.get("properties") or [],
                path=where,
            )
            breaking.extend(nested.breaking)
            relaxing.extend(nested.relaxing)

    return CompatibilityReport(
        compatible=not breaking, breaking=breaking, relaxing=relaxing
    )


def _compare_limits(
    previous: dict[str, Any],
    field: dict[str, Any],
    where: str,
    breaking: list[ValueProblem],
    relaxing: list[str],
) -> None:
    old_max = previous.get("max_length")
    new_max = field.get("max_length")
    if isinstance(old_max, int) and isinstance(new_max, int):
        if new_max < old_max:
            breaking.append(
                ValueProblem(where, f"'max_length' se estrecha de {old_max} a {new_max}")
            )
        elif new_max > old_max:
            relaxing.append(f"{where}: 'max_length' se amplia a {new_max}")

    old_min_len = previous.get("min_length") or 0
    new_min_len = field.get("min_length") or 0
    if new_min_len > old_min_len:
        breaking.append(
            ValueProblem(where, f"'min_length' se endurece de {old_min_len} a {new_min_len}")
        )

    old_items = previous.get("max_items")
    new_items = field.get("max_items")
    if isinstance(old_items, int) and isinstance(new_items, int) and new_items < old_items:
        breaking.append(
            ValueProblem(where, f"'max_items' se estrecha de {old_items} a {new_items}")
        )

    if "minimum" in field and (
        "minimum" not in previous or field["minimum"] > previous["minimum"]
    ):
        breaking.append(ValueProblem(where, "el minimo numerico se endurece"))
    if "maximum" in field and (
        "maximum" not in previous or field["maximum"] < previous["maximum"]
    ):
        breaking.append(ValueProblem(where, "el maximo numerico se endurece"))

    old_enum = previous.get("enum")
    new_enum = field.get("enum")
    if old_enum and not new_enum:
        relaxing.append(f"{where}: se elimina la lista cerrada de valores")
    elif new_enum and not old_enum:
        breaking.append(
            ValueProblem(where, "se introduce una lista cerrada de valores donde no la habia")
        )
    elif old_enum and new_enum:
        lost = [item for item in old_enum if item not in new_enum]
        if lost:
            breaking.append(
                ValueProblem(where, f"la lista cerrada pierde valores: {lost}")
            )


__all__ = [
    "CompatibilityReport",
    "FIELD_TYPES",
    "FILE_REFERENCE_SCHEMES",
    "JSON_SCHEMA_DIALECT",
    "Limits",
    "NESTED_TYPES",
    "SchemaDefinitionError",
    "ValueProblem",
    "ValuesInvalid",
    "apply_merge_patch",
    "build_json_schema",
    "check_compatibility",
    "normalize_fields",
    "sensitive_field_names",
    "validate_values",
]
