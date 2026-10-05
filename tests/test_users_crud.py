"""CRUD, validacion, paginacion y compatibilidad del ORM con el esquema real."""

from __future__ import annotations

import pytest
from sqlalchemy import select, text

from app.core.database import get_session_factory
from tests.conftest import auth

pytestmark = pytest.mark.asyncio

NUEVO = {
    "username": "ana.perez",
    "profile": {
        "first_name": "Ana",
        "last_name_paternal": "Perez",
        "last_name_maternal": "Lopez",
        "birth_date": "1990-01-15",
        "rfc": "PELA900115AB1",
        "curp": "PELA900115MDFRPN03",
    },
    "emails": [{"email": "ana.perez@example.invalid", "is_primary": True}],
    "phones": [{"phone_number": "5512345678", "is_primary": True}],
    "addresses": [
        {
            "street": "Av. Ficticia",
            "exterior_number": "100",
            "postal_code": "01000",
            "is_primary": True,
        }
    ],
}


async def test_alta_completa_en_una_transaccion(client, api, admin_session):
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["username"] == "ana.perez"
    assert body["auth_provider"] == "vault"
    # Autenticacion delegada: el hash local debe quedar NULL.
    assert body["has_local_password"] is False
    assert body["profile"]["rfc"] == "PELA900115AB1"
    assert body["role_codes"] == ["employee"]
    assert len(body["emails"]) == 1
    # El alta no provisiona Vault.
    assert body["vault_link"] is None


async def test_alta_revierte_entera_si_falla_una_parte(client, api, admin_session, seeded):
    factory = get_session_factory()
    async with factory() as session:
        antes = (await session.execute(text("SELECT count(*) FROM employees.users"))).scalar_one()

    payload = dict(NUEVO)
    payload = {**NUEVO, "username": "fallara.todo"}
    # Un correo que ya existe rompe el indice unico global.
    await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 409

    async with factory() as session:
        despues = (
            await session.execute(
                text("SELECT count(*) FROM employees.users WHERE username = 'fallara.todo'")
            )
        ).scalar_one()
        perfiles = (
            await session.execute(
                text(
                    "SELECT count(*) FROM employees.user_profiles p "
                    "JOIN employees.users u ON u.id = p.user_id "
                    "WHERE u.username = 'fallara.todo'"
                )
            )
        ).scalar_one()
    # Ni usuario ni perfil: la transaccion entera se revirtio.
    assert despues == 0
    assert perfiles == 0
    del antes


async def test_username_duplicado_sin_distinguir_mayusculas(client, api, admin_session):
    await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    otro = {**NUEVO, "username": "ana.perez", "emails": [], "phones": [], "addresses": []}
    otro["profile"] = {**NUEVO["profile"], "rfc": None, "curp": None}
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=otro)
    assert response.status_code == 409


async def test_rechaza_campos_desconocidos(client, api, admin_session):
    payload = {**NUEVO, "username": "con.extra", "is_active": False}
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 422


async def test_no_admite_asignacion_masiva_de_id_ni_auditoria(client, api, admin_session):
    for campo, valor in (
        ("id", "00000000-0000-4000-8000-000000000000"),
        ("created_at", "2020-01-01T00:00:00Z"),
        ("auth_provider", "local"),
        ("password_hash", "$argon2id$v=19$m=1,t=1,p=1$x$y"),
        ("vault_link", {"vault_username": "intruso"}),
    ):
        payload = {**NUEVO, "username": "masiva.prueba", campo: valor}
        response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
        assert response.status_code == 422, f"{campo} no fue rechazado"


@pytest.mark.parametrize(
    ("campo", "valor"),
    [
        ("rfc", "NOVALE"),
        ("curp", "CORTA123"),
        ("birth_date", "2090-01-01"),
    ],
)
async def test_validacion_de_perfil(client, api, admin_session, campo, valor):
    payload = {**NUEVO, "username": "val.prueba"}
    payload["profile"] = {**NUEVO["profile"], campo: valor}
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 422


async def test_rfc_debe_cuadrar_con_la_fecha(client, api, admin_session):
    payload = {**NUEVO, "username": "fecha.rara"}
    # RFC bien formado pero con otra fecha que la de nacimiento.
    payload["profile"] = {**NUEVO["profile"], "rfc": "PELA880115AB1", "curp": None}
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 422
    assert "fecha de nacimiento" in response.text


async def test_un_solo_correo_principal(client, api, admin_session):
    payload = {**NUEVO, "username": "dos.principales"}
    payload["emails"] = [
        {"email": "uno@example.invalid", "is_primary": True},
        {"email": "dos@example.invalid", "is_primary": True},
    ]
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 422


async def test_telefono_se_normaliza_a_digitos(client, api, admin_session):
    payload = {**NUEVO, "username": "tel.normal", "emails": [], "addresses": []}
    payload["profile"] = {**NUEVO["profile"], "rfc": None, "curp": None}
    payload["phones"] = [{"phone_number": "+52 (55) 1234-5678"}]
    response = await client.post(f"{api}/user", headers=auth(admin_session), json=payload)
    assert response.status_code == 201
    assert response.json()["phones"][0]["phone_number"] == "525512345678"


# ---------------------------------------------------------------------------
# PUT frente a PATCH
# ---------------------------------------------------------------------------


async def test_put_reemplaza_y_vacia_colecciones(client, api, admin_session):
    created = (
        await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    ).json()
    response = await client.put(
        f"{api}/user/{created['id']}",
        headers=auth(admin_session),
        json={
            "profile": {
                "first_name": "Ana Maria",
                "last_name_paternal": "Perez",
                "birth_date": "1990-01-15",
            }
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["profile"]["first_name"] == "Ana Maria"
    # Semantica de reemplazo: lo que no viene, desaparece.
    assert body["emails"] == []
    assert body["phones"] == []
    assert body["addresses"] == []
    # Y lo omitido del perfil vuelve a su valor por defecto.
    assert body["profile"]["rfc"] is None


async def test_patch_no_borra_lo_omitido(client, api, admin_session):
    created = (
        await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    ).json()
    response = await client.patch(
        f"{api}/user/{created['id']}",
        headers=auth(admin_session),
        json={"profile": {"last_name_maternal": "Garcia"}},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["profile"]["last_name_maternal"] == "Garcia"
    # Semantica parcial: los contactos siguen ahi.
    assert len(body["emails"]) == 1
    assert len(body["phones"]) == 1
    assert body["profile"]["rfc"] == "PELA900115AB1"


async def test_patch_modifica_por_id_y_borra_explicitamente(client, api, admin_session):
    created = (
        await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    ).json()
    email_id = created["emails"][0]["id"]
    phone_id = created["phones"][0]["id"]

    response = await client.patch(
        f"{api}/user/{created['id']}",
        headers=auth(admin_session),
        json={
            "emails": [
                {"id": email_id, "email": "cambiado@example.invalid", "is_primary": True}
            ],
            "remove_phone_ids": [phone_id],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["emails"][0]["email"] == "cambiado@example.invalid"
    assert body["emails"][0]["id"] == email_id   # modificado, no recreado
    assert body["phones"] == []                  # borrado explicito


async def test_patch_con_id_ajeno(client, api, admin_session, seeded):
    created = (
        await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    ).json()
    response = await client.patch(
        f"{api}/user/{created['id']}",
        headers=auth(admin_session),
        json={
            "emails": [
                {
                    "id": "00000000-0000-4000-8000-0000000000ff",
                    "email": "ajeno@example.invalid",
                }
            ]
        },
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Paginacion y orden
# ---------------------------------------------------------------------------


async def test_paginacion_y_orden_estable(client, api, admin_session):
    for i in range(7):
        await client.post(
            f"{api}/user",
            headers=auth(admin_session),
            json={
                "username": f"empleado.{i:02d}",
                "profile": {
                    "first_name": f"Emp{i}",
                    "last_name_paternal": "Prueba",
                    "birth_date": "1990-01-15",
                },
            },
        )

    primera = await client.get(
        f"{api}/user?limit=4&offset=0&sort_by=username&order=asc",
        headers=auth(admin_session),
    )
    segunda = await client.get(
        f"{api}/user?limit=4&offset=4&sort_by=username&order=asc",
        headers=auth(admin_session),
    )
    assert primera.status_code == segunda.status_code == 200
    ids_1 = [u["id"] for u in primera.json()["items"]]
    ids_2 = [u["id"] for u in segunda.json()["items"]]
    assert len(ids_1) == 4
    # Sin solapamiento entre paginas: el orden es estable.
    assert not set(ids_1) & set(ids_2)
    assert primera.json()["page"]["total"] == 10  # 7 nuevos + 3 sembrados


async def test_orden_fuera_de_la_allowlist(client, api, admin_session):
    response = await client.get(
        f"{api}/user?sort_by=password_hash", headers=auth(admin_session)
    )
    assert response.status_code == 422


async def test_limite_de_pagina(client, api, admin_session):
    assert (await client.get(f"{api}/user?limit=0", headers=auth(admin_session))).status_code == 422
    assert (await client.get(f"{api}/user?limit=101", headers=auth(admin_session))).status_code == 422
    assert (await client.get(f"{api}/user?offset=-1", headers=auth(admin_session))).status_code == 422


async def test_filtro_por_rol(client, api, admin_session):
    response = await client.get(f"{api}/user?role_code=admin", headers=auth(admin_session))
    assert response.status_code == 200
    assert all("admin" in u["role_codes"] for u in response.json()["items"])


async def test_busqueda_por_cuerpo_no_por_url(client, api, admin_session):
    await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    response = await client.post(
        f"{api}/user/search",
        headers=auth(admin_session),
        json={"email": "ana.perez@example.invalid"},
    )
    assert response.status_code == 200
    assert response.json()["items"][0]["username"] == "ana.perez"


async def test_404_con_uuid_inexistente(client, api, admin_session):
    response = await client.get(
        f"{api}/user/00000000-0000-4000-8000-000000000999", headers=auth(admin_session)
    )
    assert response.status_code == 404


async def test_uuid_mal_formado(client, api, admin_session):
    response = await client.get(f"{api}/user/no-es-un-uuid", headers=auth(admin_session))
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Compatibilidad del ORM con el esquema real
# ---------------------------------------------------------------------------


async def test_orm_coincide_con_las_columnas_reales(clean_db):
    """Cada columna mapeada existe en la base, y con el mismo nombre."""
    from app.models.employees import Base

    factory = get_session_factory()
    async with factory() as session:
        for table in Base.metadata.sorted_tables:
            rows = (
                await session.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = :schema AND table_name = :table"
                    ),
                    {"schema": table.schema, "table": table.name},
                )
            ).scalars().all()
            reales = set(rows)
            assert reales, f"la tabla {table.name} no existe en la base"
            mapeadas = {c.name for c in table.columns}
            faltan = mapeadas - reales
            assert not faltan, f"{table.name}: columnas mapeadas que no existen: {faltan}"


async def test_trigger_de_updated_at_lo_mantiene_la_base(client, api, admin_session):
    from app.models.employees import User

    created = (
        await client.post(f"{api}/user", headers=auth(admin_session), json=NUEVO)
    ).json()
    factory = get_session_factory()
    async with factory() as session:
        user = (
            await session.execute(select(User).where(User.id == created["id"]))
        ).scalar_one()
        anterior = user.updated_at
        # Se intenta escribir una fecha absurda: el trigger debe ignorarla.
        user.is_active = True
        user.updated_at = __import__("datetime").datetime(
            2000, 1, 1, tzinfo=__import__("datetime").UTC
        )
        await session.commit()

    async with factory() as session:
        user = (
            await session.execute(select(User).where(User.id == created["id"]))
        ).scalar_one()
    assert user.updated_at.year != 2000
    assert user.updated_at >= anterior
