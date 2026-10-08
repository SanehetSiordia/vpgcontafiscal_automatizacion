"""Pruebas unitarias del esquema tipado, con dobles no: solo funciones puras.

Este modulo no toca red ni base de datos. Comprueba las tres piezas de
``app/core/secret_schema.py``:

1. la **definicion** de campos se valida y se canoniza;
2. el **documento JSON Schema** generado es Draft 2020-12, autocontenido y sin
   ``$ref``;
3. la **validacion de valores** acepta y rechaza lo que debe, y el JSON Merge
   Patch tiene la semantica de la RFC 7386.

Tambien se comprueba el limite declarado del validador: cubre el subconjunto
que este servicio genera, y el documento que publica es estandar para que un
validador externo pueda comprobar lo mismo.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.core.secret_schema import (
    JSON_SCHEMA_DIALECT,
    Limits,
    SchemaDefinitionError,
    ValuesInvalid,
    apply_merge_patch,
    build_json_schema,
    check_compatibility,
    normalize_fields,
    sensitive_field_names,
    validate_values,
)

LIMITS = Limits(
    max_fields_per_schema=50,
    max_field_name_length=64,
    max_string_value_length=4096,
    max_object_depth=4,
    max_array_items=100,
    max_record_bytes=65536,
)

CAMPOS = [
    {"name": "usuario", "type": "string", "required": True, "max_length": 64},
    {
        "name": "password",
        "type": "string",
        "required": True,
        "sensitive": True,
        "max_length": 256,
    },
    {"name": "intentos", "type": "integer", "minimum": 0, "maximum": 10},
    {"name": "activo", "type": "boolean"},
    {"name": "entorno", "type": "string", "enum": ["produccion", "pruebas"]},
]


def documento(campos=None):
    campos = normalize_fields(campos or CAMPOS, limits=LIMITS)
    return campos, build_json_schema(
        campos,
        collection_id=uuid.UUID("3f2a7c18-2d44-4a90-9f4c-1b5e6a7d8c90"),
        schema_version=1,
        logical_name="sat/usuarios",
    )


# ---------------------------------------------------------------------------
# 1. Definicion
# ---------------------------------------------------------------------------


def test_la_definicion_se_canoniza():
    campos = normalize_fields(CAMPOS, limits=LIMITS)
    assert [campo["name"] for campo in campos] == [
        "usuario",
        "password",
        "intentos",
        "activo",
        "entorno",
    ]
    # Los valores por omision quedan explicitos.
    assert campos[2]["required"] is False
    assert campos[2]["sensitive"] is False
    # Un string sin max_length recibe el tope de la configuracion.
    (solo,) = normalize_fields([{"name": "x", "type": "string"}], limits=LIMITS)
    assert solo["max_length"] == LIMITS.max_string_value_length


def test_sensitive_es_una_etiqueta_no_una_proteccion():
    campos = normalize_fields(CAMPOS, limits=LIMITS)
    assert sensitive_field_names(campos) == frozenset({"password"})
    # Y no cambia la validacion: un campo sensible se valida igual que otro.
    _, esquema = documento()
    validate_values(
        {"usuario": "demo", "password": "x" * 256}, esquema, fields=campos
    )
    with pytest.raises(ValuesInvalid):
        validate_values(
            {"usuario": "demo", "password": "x" * 257}, esquema, fields=campos
        )


@pytest.mark.parametrize(
    ("campo", "motivo"),
    [
        ({"type": "string"}, "falta 'name'"),
        ({"name": "Mayuscula", "type": "string"}, "minusculas"),
        ({"name": "con-guion", "type": "string"}, "minusculas"),
        ({"name": "1empieza", "type": "string"}, "minusculas"),
        ({"name": "x", "type": "inventado"}, "no admitido"),
        ({"name": "x", "type": "string", "max_length": 0}, "entre 1"),
        ({"name": "x", "type": "string", "max_length": 99999}, "entre 1"),
        ({"name": "x", "type": "integer", "minimum": 10, "maximum": 1}, "superar"),
        ({"name": "x", "type": "array", "items_type": "array"}, "no admitido"),
    ],
)
def test_definiciones_invalidas(campo, motivo):
    with pytest.raises(SchemaDefinitionError) as error:
        normalize_fields([campo], limits=LIMITS)
    assert motivo in str(error.value)


def test_nombres_duplicados():
    with pytest.raises(SchemaDefinitionError) as error:
        normalize_fields(
            [
                {"name": "x", "type": "string"},
                {"name": "x", "type": "integer"},
            ],
            limits=LIMITS,
        )
    assert "duplicado" in str(error.value)


def test_un_esquema_vacio_no_vale():
    with pytest.raises(SchemaDefinitionError):
        normalize_fields([], limits=LIMITS)


def test_la_profundidad_esta_acotada():
    """``max_object_depth=4`` admite cuatro niveles y rechaza el quinto."""
    cabe = {
        "name": "a",
        "type": "object",
        "properties": [
            {
                "name": "b",
                "type": "object",
                "properties": [
                    {
                        "name": "c",
                        "type": "object",
                        "properties": [{"name": "d", "type": "string"}],
                    }
                ],
            }
        ],
    }
    normalize_fields([cabe], limits=LIMITS)

    no_cabe = {
        "name": "a",
        "type": "object",
        "properties": [
            {
                "name": "b",
                "type": "object",
                "properties": [
                    {
                        "name": "c",
                        "type": "object",
                        "properties": [
                            {
                                "name": "d",
                                "type": "object",
                                "properties": [{"name": "e", "type": "string"}],
                            }
                        ],
                    }
                ],
            }
        ],
    }
    with pytest.raises(SchemaDefinitionError) as error:
        normalize_fields([no_cabe], limits=LIMITS)
    assert "profundidad" in str(error.value)


# ---------------------------------------------------------------------------
# 2. Documento JSON Schema
# ---------------------------------------------------------------------------


def test_el_documento_es_draft_2020_12_y_autocontenido():
    _campos, esquema = documento()
    assert esquema["$schema"] == JSON_SCHEMA_DIALECT
    assert esquema["$id"].startswith("urn:vpg:vault-mgmt:collection:")
    assert esquema["type"] == "object"
    # Cerrado: un campo no declarado no entra. Es lo que permite afirmar que el
    # registro es una tupla conocida.
    assert esquema["additionalProperties"] is False
    assert esquema["required"] == ["usuario", "password"]
    # Sin referencias de ningun tipo: no se resuelve ninguna URI al validar.
    serializado = json.dumps(esquema)
    for prohibido in ("$ref", "$defs", "$dynamicRef", "$anchor"):
        assert prohibido not in serializado
    # El $id es un URN informativo, no una direccion descargable.
    assert "http://" not in esquema["$id"]
    assert "https://" not in esquema["$id"]
    # Los campos sensibles se anotan, no se validan de otra forma.
    assert esquema["x-vpg-sensitive-fields"] == ["password"]


def test_file_reference_es_una_referencia_no_el_contenido():
    campos, esquema = documento(
        [{"name": "acuse", "type": "file_reference", "required": True}]
    )
    nodo = esquema["properties"]["acuse"]
    assert nodo["type"] == "object"
    assert nodo["required"] == ["uri"]
    assert nodo["additionalProperties"] is False
    assert set(nodo["properties"]) == {"uri", "media_type", "digest_sha256", "size_bytes"}
    assert "no guarda el contenido" in nodo["description"]

    validate_values(
        {"acuse": {"uri": "s3://bucket/acuse.pdf", "media_type": "application/pdf"}},
        esquema,
        fields=campos,
    )

    # Esquema de URI fuera de la allowlist.
    with pytest.raises(ValuesInvalid) as error:
        validate_values(
            {"acuse": {"uri": "ftp://servidor/acuse.pdf"}}, esquema, fields=campos
        )
    assert any("esquema de URI" in p.reason for p in error.value.problems)

    # Y nada de contenido en linea: 'base64' no es un campo declarado.
    with pytest.raises(ValuesInvalid):
        validate_values(
            {"acuse": {"uri": "file://x.pdf", "base64": "QUJD"}},
            esquema,
            fields=campos,
        )

    # Un digest que no es SHA-256 hexadecimal se rechaza. Y conviene recordar
    # que un hash NO es cifrado: no sustituye al archivo.
    with pytest.raises(ValuesInvalid) as error:
        validate_values(
            {"acuse": {"uri": "file://x.pdf", "digest_sha256": "no-es-un-digest"}},
            esquema,
            fields=campos,
        )
    assert any("SHA-256" in p.reason for p in error.value.problems)


# ---------------------------------------------------------------------------
# 3. Validacion de valores
# ---------------------------------------------------------------------------


def test_la_tupla_valida_pasa():
    campos, esquema = documento()
    validate_values(
        {
            "usuario": "demo",
            "password": "valor-ficticio",
            "intentos": 3,
            "activo": True,
            "entorno": "pruebas",
        },
        esquema,
        fields=campos,
    )


@pytest.mark.parametrize(
    ("valores", "campo_esperado"),
    [
        ({"usuario": "demo"}, "values.password"),
        ({"usuario": "demo", "password": "x", "sobra": 1}, "values.sobra"),
        ({"usuario": 1, "password": "x"}, "values.usuario"),
        ({"usuario": "demo", "password": "x", "intentos": "tres"}, "values.intentos"),
        ({"usuario": "demo", "password": "x", "intentos": 99}, "values.intentos"),
        ({"usuario": "demo", "password": "x", "activo": "si"}, "values.activo"),
        ({"usuario": "demo", "password": "x", "entorno": "otro"}, "values.entorno"),
        ({"usuario": "d" * 65, "password": "x"}, "values.usuario"),
    ],
)
def test_tuplas_invalidas(valores, campo_esperado):
    campos, esquema = documento()
    with pytest.raises(ValuesInvalid) as error:
        validate_values(valores, esquema, fields=campos)
    assert any(p.field == campo_esperado for p in error.value.problems)


def test_un_booleano_no_es_un_entero():
    """``True`` es ``int`` en Python, pero no es un entero en JSON Schema."""
    campos, esquema = documento()
    with pytest.raises(ValuesInvalid):
        validate_values(
            {"usuario": "demo", "password": "x", "intentos": True},
            esquema,
            fields=campos,
        )


def test_el_mensaje_nombra_los_valores_admitidos_no_el_enviado():
    campos, esquema = documento()
    with pytest.raises(ValuesInvalid) as error:
        validate_values(
            {"usuario": "demo", "password": "secreto-que-no-debe-salir", "entorno": "x"},
            esquema,
            fields=campos,
        )
    texto = " ".join(p.reason for p in error.value.problems)
    # El enum lo declara el esquema y no es un secreto: se puede nombrar.
    assert "produccion" in texto
    # El valor enviado, no.
    assert "secreto-que-no-debe-salir" not in texto
    assert "x" not in [p.reason for p in error.value.problems]


def test_el_tope_de_tamano_del_registro():
    campos, esquema = documento()
    pequeno = Limits(50, 64, 4096, 4, 100, 64)
    with pytest.raises(ValuesInvalid) as error:
        validate_values(
            {"usuario": "demo", "password": "x" * 200},
            esquema,
            fields=campos,
            max_record_bytes=pequeno.max_record_bytes,
        )
    assert any("bytes" in p.reason for p in error.value.problems)


def test_objetos_y_listas_anidadas():
    campos, esquema = documento(
        [
            {
                "name": "contacto",
                "type": "object",
                "required": True,
                "properties": [
                    {"name": "correo", "type": "string", "required": True},
                    {"name": "telefono", "type": "string"},
                ],
            },
            {
                "name": "etiquetas",
                "type": "array",
                "items_type": "string",
                "max_items": 2,
                "max_length": 10,
            },
        ]
    )
    validate_values(
        {"contacto": {"correo": "a@example.invalid"}, "etiquetas": ["uno", "dos"]},
        esquema,
        fields=campos,
    )

    with pytest.raises(ValuesInvalid) as error:
        validate_values({"contacto": {}}, esquema, fields=campos)
    assert any(p.field == "values.contacto.correo" for p in error.value.problems)

    with pytest.raises(ValuesInvalid) as error:
        validate_values(
            {"contacto": {"correo": "a@example.invalid"}, "etiquetas": ["a", "b", "c"]},
            esquema,
            fields=campos,
        )
    assert any("excede 2 elementos" in p.reason for p in error.value.problems)


# ---------------------------------------------------------------------------
# 4. JSON Merge Patch
# ---------------------------------------------------------------------------


def test_merge_patch_omite_conserva_y_null_elimina():
    actual = {"usuario": "demo", "password": "viejo", "rfc": "XAXX010101000"}
    resultado = apply_merge_patch(actual, {"password": "nuevo", "rfc": None})
    assert resultado == {"usuario": "demo", "password": "nuevo"}
    # El original no se muta.
    assert actual["rfc"] == "XAXX010101000"


def test_merge_patch_mezcla_objetos_y_reemplaza_listas():
    actual = {
        "contacto": {"correo": "a@example.invalid", "telefono": "555"},
        "etiquetas": ["uno", "dos"],
    }
    resultado = apply_merge_patch(
        actual, {"contacto": {"telefono": None}, "etiquetas": ["tres"]}
    )
    # El objeto se mezcla de forma recursiva: 'correo' sobrevive.
    assert resultado["contacto"] == {"correo": "a@example.invalid"}
    # La lista se reemplaza entera, no se concatena.
    assert resultado["etiquetas"] == ["tres"]


def test_un_patch_vacio_no_cambia_nada():
    actual = {"usuario": "demo"}
    assert apply_merge_patch(actual, {}) == actual


# ---------------------------------------------------------------------------
# 5. Compatibilidad entre versiones
# ---------------------------------------------------------------------------


def test_cambios_seguros():
    viejos = normalize_fields(CAMPOS, limits=LIMITS)
    nuevos = normalize_fields(
        CAMPOS
        + [{"name": "notas", "type": "string", "required": False, "max_length": 500}],
        limits=LIMITS,
    )
    informe = check_compatibility(viejos, nuevos)
    assert informe.compatible is True
    assert any("campo opcional nuevo" in cambio for cambio in informe.relaxing)


def test_relajar_un_obligatorio_y_ampliar_un_limite_son_seguros():
    viejos = normalize_fields(
        [{"name": "x", "type": "string", "required": True, "max_length": 10}],
        limits=LIMITS,
    )
    nuevos = normalize_fields(
        [{"name": "x", "type": "string", "required": False, "max_length": 20}],
        limits=LIMITS,
    )
    informe = check_compatibility(viejos, nuevos)
    assert informe.compatible is True
    assert len(informe.relaxing) == 2


@pytest.mark.parametrize(
    ("nuevos_campos", "motivo"),
    [
        ([], "desaparece"),
        (
            [
                {"name": "x", "type": "string", "required": True, "max_length": 10},
                {"name": "y", "type": "string", "required": True},
            ],
            "campo nuevo obligatorio",
        ),
        (
            [{"name": "x", "type": "integer", "required": True}],
            "el tipo cambia",
        ),
        (
            [{"name": "x", "type": "string", "required": True, "max_length": 5}],
            "se estrecha",
        ),
        (
            [
                {
                    "name": "x",
                    "type": "string",
                    "required": True,
                    "max_length": 10,
                    "enum": ["a"],
                }
            ],
            "lista cerrada",
        ),
    ],
)
def test_cambios_que_rompen(nuevos_campos, motivo):
    viejos = normalize_fields(
        [{"name": "x", "type": "string", "required": True, "max_length": 10}],
        limits=LIMITS,
    )
    nuevos = normalize_fields(nuevos_campos, limits=LIMITS) if nuevos_campos else []
    informe = check_compatibility(viejos, nuevos)
    assert informe.compatible is False
    razones = " ".join(problema.reason for problema in informe.breaking)
    assert motivo in razones
    # El diagnostico habla de campos, nunca de valores almacenados.
    assert all(problema.field.startswith("fields") for problema in informe.breaking)


def test_un_obligatorio_que_pasa_a_opcional_no_rompe_pero_al_reves_si():
    opcional = normalize_fields([{"name": "x", "type": "string"}], limits=LIMITS)
    obligatorio = normalize_fields(
        [{"name": "x", "type": "string", "required": True}], limits=LIMITS
    )
    assert check_compatibility(obligatorio, opcional).compatible is True
    assert check_compatibility(opcional, obligatorio).compatible is False


def test_el_informe_se_puede_serializar_para_la_respuesta():
    viejos = normalize_fields([{"name": "x", "type": "string"}], limits=LIMITS)
    informe = check_compatibility(viejos, [])
    como_dict = informe.as_dict()
    assert como_dict["compatible"] is False
    assert como_dict["breaking_changes"][0]["field"] == "fields.x"
    # Serializable sin sorpresas: va dentro de un cuerpo JSON de error 409.
    json.dumps(como_dict)
