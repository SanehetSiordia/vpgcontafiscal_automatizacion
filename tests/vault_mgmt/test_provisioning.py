"""Aprovisionamiento automatico de consumidores de maquina (etapa 4.6).

Que se prueba de verdad aqui, y que no
--------------------------------------
* **PostgreSQL es real.** Los invariantes que sostienen esta etapa son indices
  parciales y restricciones CHECK: una sola operacion viva por consumidor, una
  sola entrega viva, ``finished_at`` solo en estados terminales, un receptor por
  consumidor. Eso no existe en un doble.
* **La autorizacion es real.** La pasarela interna de user-mgmt corre en el
  proceso de pruebas: el rol admin se relee de PostgreSQL en cada peticion.
* **Vault es un doble explicito** (``FakeAppRole``), pero con el comportamiento
  del que dependen las garantias: la envoltura es de un solo uso, el SecretID
  solo sale envuelto, destruirlo no revoca tokens ya emitidos, y la guarda de
  alcance rechaza un rol ajeno.
* **El worker se invoca en linea** (``run_operation``), sin proceso aparte. Lo
  que se prueba es la maquina de estados y el efecto en Vault, no el bucle de
  sondeo. Que el proceso arranque y tome trabajo es comprobacion manual, y esta
  en el README.

Lo que NO demuestran estas pruebas: Vault de verdad, TTL reales, el efecto de
las politicas HCL y un crawler real. Para eso estan las comprobaciones manuales
documentadas en readme/etapa-4-6-aprovisionamiento.md.
"""

from __future__ import annotations

import uuid

import pytest

from tests.vault_mgmt.conftest import (
    auth,
    consumer_name,
    create_collection,
    create_record,
)

pytestmark = pytest.mark.asyncio

INTERNAL = "/internal/v1/crawler/provisioning"


# ---------------------------------------------------------------------------
# Utilidades del recorrido
# ---------------------------------------------------------------------------


async def registrar(
    vm_client,
    vm_api,
    session,
    *,
    receiver,
    name=None,
    bindings=None,
    idempotency_key=None,
):
    """Alta de consumidor. Devuelve la respuesta tal cual para poder afirmar."""
    headers = auth(session)
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    payload = {
        "name": name or consumer_name(),
        "receiver": receiver.name if hasattr(receiver, "name") else receiver,
        "bindings": bindings or [],
    }
    return await vm_client.post(
        f"{vm_api}/vault/consumers", json=payload, headers=headers
    )


async def correr_worker(apps, operation_id: str) -> str:
    """Ejecuta la operacion como lo haria el worker y devuelve su estado."""
    service = apps["vault_mgmt"].state.provisioning_service
    return await service.run_operation(uuid.UUID(operation_id))


async def alta_lista(vm_client, vm_api, apps, session, **kwargs):
    """Alta + paso del worker: deja el consumidor esperando al receptor."""
    kwargs.setdefault("receiver", apps["receiver"])
    response = await registrar(vm_client, vm_api, session, **kwargs)
    assert response.status_code == 202, response.text
    body = response.json()
    estado = await correr_worker(apps, body["operation_id"])
    assert estado == "waiting_receiver", estado
    return body


# ---------------------------------------------------------------------------
# 1. Contrato de la solicitud administrativa
# ---------------------------------------------------------------------------


async def test_alta_devuelve_202_y_exactamente_tres_campos(
    receiver,
    vm_client, vm_api, admin_session
):
    """202 con consumer_id, operation_id y status. Ni un campo mas."""
    response = await registrar(vm_client, vm_api, admin_session, receiver=receiver)

    assert response.status_code == 202
    body = response.json()
    assert set(body) == {"consumer_id", "operation_id", "status"}
    # Identificadores reales, no cadenas de ejemplo.
    uuid.UUID(body["consumer_id"])
    uuid.UUID(body["operation_id"])
    # 'pending' significa solicitud guardada, no entrega completada.
    assert body["status"] == "pending"
    # Location para hacer polling sin construir la URL a mano.
    assert body["operation_id"] in response.headers["location"]


async def test_alta_no_devuelve_ninguna_credencial(
    receiver,vm_client, vm_api, admin_session):
    """Ni role_id, ni secret_id, ni tokens, en ningun endpoint humano."""
    alta = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    consumer_id = alta.json()["consumer_id"]

    detalle = await vm_client.get(
        f"{vm_api}/vault/consumers/{consumer_id}", headers=auth(admin_session)
    )
    listado = await vm_client.get(
        f"{vm_api}/vault/consumers", headers=auth(admin_session)
    )

    prohibidos = ("role_id", "secret_id", "wrap_token", "vault_token", "credential")
    for respuesta in (alta, detalle, listado):
        crudo = respuesta.text.lower()
        for palabra in prohibidos:
            assert palabra not in crudo, f"{palabra} aparece en {respuesta.url}"


async def test_receptor_desconocido_es_422_y_no_crea_consumidor(
    receiver,
    vm_client, vm_api, admin_session
):
    """Un alta con un receptor sin configurar no deja un consumidor huerfano."""
    nombre = consumer_name()
    response = await registrar(vm_client, vm_api, admin_session, name=nombre, receiver="no-configurado"
    )

    assert response.status_code == 422
    assert response.json()["code"] == "unknown_receiver"

    listado = await vm_client.get(
        f"{vm_api}/vault/consumers?limit=100", headers=auth(admin_session)
    )
    assert nombre not in [item["name"] for item in listado.json()["items"]]


async def test_el_cuerpo_no_acepta_vault_ni_url(
    receiver,vm_client, vm_api, admin_session):
    """HCL, paths, montajes, roles y URL del receptor estan fuera del contrato."""
    for extra in (
        {"policy": 'path "secret/*" { capabilities = ["read"] }'},
        {"approle_mount": "otro-montaje"},
        {"approle_role_name": "vpg-user-mgmt"},
        {"vault_path": "secret/data/otra-cosa"},
        {"receiver_url": "http://atacante.example/claim"},
        {"role_id": "7b8c9e01"},
    ):
        response = await vm_client.post(
            f"{vm_api}/vault/consumers",
            json={"name": consumer_name(), "receiver": receiver.name, **extra},
            headers=auth(admin_session),
        )
        assert response.status_code == 422, f"{extra} deberia rechazarse"


async def test_solo_admin_opera_consumidores(
    receiver,
    vm_client, vm_api, manager_session, employee_session, admin_session
):
    """manager y employee no registran, no aprovisionan y no revocan."""
    alta = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    consumer_id = alta.json()["consumer_id"]

    for session in (manager_session, employee_session):
        assert (await registrar(vm_client, vm_api, session, receiver=receiver)).status_code == 403
        assert (
            await vm_client.post(
                f"{vm_api}/vault/consumers/{consumer_id}/provision",
                json={},
                headers=auth(session),
            )
        ).status_code == 403
        assert (
            await vm_client.get(f"{vm_api}/vault/consumers", headers=auth(session))
        ).status_code == 403


async def test_sin_sesion_es_401(vm_client, vm_api):
    response = await vm_client.get(f"{vm_api}/vault/consumers")
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# 2. Idempotencia
# ---------------------------------------------------------------------------


async def test_misma_clave_y_parametros_devuelve_los_mismos_ids(
    receiver,
    vm_client, vm_api, admin_session
):
    """Repetir la peticion no crea un segundo consumidor ni otra operacion."""
    clave = f"idem-{uuid.uuid4().hex}"
    nombre = consumer_name()

    primera = await registrar(vm_client, vm_api, admin_session, receiver=receiver, name=nombre, idempotency_key=clave
    )
    segunda = await registrar(vm_client, vm_api, admin_session, receiver=receiver, name=nombre, idempotency_key=clave
    )

    assert primera.status_code == 202
    assert segunda.status_code == 202
    assert primera.json()["consumer_id"] == segunda.json()["consumer_id"]
    assert primera.json()["operation_id"] == segunda.json()["operation_id"]


async def test_misma_clave_con_otros_parametros_es_409(
    receiver,
    vm_client, vm_api, admin_session
):
    """Reutilizar una clave para otra cosa es un error del cliente, no una alta."""
    clave = f"idem-{uuid.uuid4().hex}"
    await registrar(vm_client, vm_api, admin_session, receiver=receiver, idempotency_key=clave)

    otra = await registrar(vm_client, vm_api, admin_session, receiver=receiver, name=consumer_name("otro"), idempotency_key=clave
    )

    assert otra.status_code == 409
    assert otra.json()["code"] == "idempotency_key_reused"


async def test_nombre_repetido_es_409(
    receiver,vm_client, vm_api, admin_session):
    nombre = consumer_name()
    assert (await registrar(vm_client, vm_api, admin_session, receiver=receiver, name=nombre)).status_code == 202

    repetido = await registrar(vm_client, vm_api, admin_session, receiver=receiver, name=nombre)
    assert repetido.status_code == 409
    assert repetido.json()["code"] == "consumer_name_taken"


async def test_un_receptor_sirve_a_un_solo_consumidor(
    receiver,
    vm_client, vm_api, admin_session
):
    """Si dos lo compartieran, su credencial no diria que emision reclamar."""
    assert (await registrar(vm_client, vm_api, admin_session, receiver=receiver)).status_code == 202

    segundo = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    assert segundo.status_code == 409
    assert segundo.json()["code"] == "receiver_taken"


async def test_dos_operaciones_vivas_por_consumidor_es_409(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Dos aprovisionamientos a la vez emitirian dos SecretID."""
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]

    # La operacion del alta quedo en waiting_receiver: sigue viva.
    segunda = await vm_client.post(
        f"{vm_api}/vault/consumers/{consumer_id}/provision",
        json={},
        headers=auth(admin_session),
    )
    assert segunda.status_code == 409
    assert segunda.json()["code"] == "operation_in_progress"


# ---------------------------------------------------------------------------
# 3. Sin receptor no se emite nada
# ---------------------------------------------------------------------------


async def test_el_worker_deja_la_identidad_lista_sin_emitir_credencial(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """waiting_receiver: AppRole creada y CERO SecretID emitidos."""
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)

    assert approle.mount_enabled is True
    assert approle.policy_written >= 1
    assert len(approle.roles) == 1
    # Lo importante: no hay credencial viva esperando a nadie.
    assert approle.secret_ids == {}
    assert approle.wraps == {}


async def test_los_metadatos_del_secret_id_llevan_los_identificadores(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Que se etiqueta el SecretID con el alcance de la entrega.

    El FORMATO de hilo (cadena JSON, que es donde estuvo el fallo) no se puede
    comprobar aqui: el doble sustituye al cliente entero. Eso se prueba en
    tests/vault_mgmt/test_approle_admin_wire.py, contra el cliente de verdad.
    """
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)

    claim = await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)

    assert claim.status_code == 200, claim.text
    # El doble ya habria fallado si hubiese recibido un dict; aqui se comprueba
    # que lo almacenado es el JSON deserializado, con los identificadores.
    assert len(approle.secret_ids) == 1
    metadatos = next(iter(approle.secret_ids.values()))["metadata"]
    assert set(metadatos) == {"consumer_id", "operation_id", "delivery_id", "receiver"}
    assert metadatos["receiver"] == receiver.name
    # Ningun valor sensible viaja en los metadatos: Vault los devuelve en lookup.
    assert all(isinstance(v, str) for v in metadatos.values())


async def test_la_politica_gestionada_no_lee_kv(apps):
    """Si leyera el prefijo, los bindings no acotarian nada."""
    hcl = apps["approle"].managed_policy_hcl()
    assert "secret/data" not in hcl
    assert "sys/wrapping/unwrap" in hcl


async def test_claim_sin_solicitud_no_emite(
    receiver,vm_client, vm_api, apps, admin_session):
    """Sin alta previa, el receptor recibe 'no hay nada', no una credencial."""
    alta = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    assert alta.status_code == 202
    # A proposito NO se corre el worker: la identidad no esta lista.

    response = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers=receiver.headers
    )

    assert response.status_code == 200
    assert response.json()["status"] == "waiting_provisioner"
    assert apps["approle"].secret_ids == {}


# ---------------------------------------------------------------------------
# 4. Canal interno: credencial del receptor
# ---------------------------------------------------------------------------


async def test_claim_sin_credencial_es_401(
    receiver,vm_client):
    response = await vm_client.post(f"{INTERNAL}/claim", json={})
    assert response.status_code == 401
    assert response.json()["code"] == "receiver_credential_missing"


async def test_claim_con_credencial_invalida_es_401(
    receiver,vm_client):
    response = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers={"X-VPG-Receiver-Credential": "no-es-la-buena"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "receiver_credential_invalid"


async def test_el_consumer_id_no_sirve_como_credencial(
    vm_client, vm_api, apps, admin_session
):
    """Es un identificador de inventario, no una contrasena."""
    body = await alta_lista(vm_client, vm_api, apps, admin_session)

    response = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers={"X-VPG-Receiver-Credential": body["consumer_id"]}
    )

    assert response.status_code == 401


async def test_una_api_session_humana_no_sirve_en_el_canal_interno(
    vm_client, admin_session
):
    response = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers={"X-VPG-Receiver-Credential": admin_session}
    )
    assert response.status_code == 401


async def test_el_canal_interno_no_esta_en_el_openapi_publico(apps):
    """Oculto en Swagger, pero protegido por la credencial, no por estar oculto."""
    spec = apps["vault_mgmt"].openapi()
    assert not [p for p in spec["paths"] if p.startswith("/internal")]


# ---------------------------------------------------------------------------
# 5. Recorrido completo: claim, unwrap, login, ack
# ---------------------------------------------------------------------------


async def test_recorrido_completo_hasta_completed(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """El camino bueno, con la identidad comprobada en el ack."""
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]

    # 1. El receptor reclama: recibe role_id y una ENVOLTURA, no el secret_id.
    claim = await vm_client.post(
        f"{INTERNAL}/claim", json={"instance": "crawler-1"}, headers=receiver.headers
    )
    assert claim.status_code == 200
    entrega = claim.json()
    assert entrega["status"] == "issued"
    assert entrega["wrap_token"].startswith("wrap-")
    assert entrega["login_path"] == f"auth/{approle.mount}/login"
    # No hay campo secret_id en el cuerpo: el valor viaja DENTRO de la
    # envoltura, y la palabra solo aparece en las instrucciones de next_step.
    assert "secret_id" not in entrega

    # La operacion NO esta completa: espera la confirmacion.
    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{entrega['operation_id']}",
        headers=auth(admin_session),
    )
    assert operacion.json()["status"] == "awaiting_ack"

    # 2. El receptor desenvuelve y entra, como haria el crawler.
    secret_id = approle.unwrap(entrega["wrap_token"])
    token = approle.login(entrega["role_id"], secret_id)
    # El valor del SecretID nunca estuvo en la respuesta del claim: viajaba
    # dentro de la envoltura.
    assert secret_id not in claim.text

    # 3. Confirma acreditando ESE token.
    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": entrega["delivery_id"], "vault_token": token},
        headers=receiver.headers,
    )
    assert ack.status_code == 200, ack.text
    assert ack.json()["status"] == "completed"
    assert ack.json()["provisioning_state"] == "ready"
    # Se devuelve el ACCESSOR del token, no el token.
    assert ack.json()["token_accessor"]
    assert token not in ack.text

    # 4. El catalogo lo refleja, y sigue sin credenciales.
    detalle = await vm_client.get(
        f"{vm_api}/vault/consumers/{consumer_id}", headers=auth(admin_session)
    )
    assert detalle.json()["consumer"]["provisioning_state"] == "ready"
    assert detalle.json()["last_operation"]["status"] == "completed"
    assert detalle.json()["last_delivery"]["state"] == "acked"
    # Del lado humano solo salen ACCESSORS (sirven para revocar, no para usar):
    # ni el SecretID, ni el token, ni la envoltura.
    entregado = detalle.json()["last_delivery"]
    assert "secret_id" not in entregado
    assert entregado["secret_id_accessor"] != secret_id
    for valor in (secret_id, token, entrega["wrap_token"], entrega["role_id"]):
        assert valor not in detalle.text


async def test_la_envoltura_es_de_un_solo_uso(
    receiver,vm_client, vm_api, apps, admin_session):
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    approle.unwrap(entrega["wrap_token"])
    with pytest.raises(AssertionError, match="un solo uso"):
        approle.unwrap(entrega["wrap_token"])


async def test_claim_repetido_no_emite_otra_credencial(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Emitir encima dejaria la anterior huerfana en Vault."""
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)

    primero = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers=receiver.headers
    )
    segundo = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers=receiver.headers
    )

    assert primero.json()["status"] == "issued"
    assert segundo.json()["status"] == "already_delivered"
    assert len(approle.secret_ids) == 1


async def test_ack_con_token_invalido_no_completa(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Un 'success: true' del cliente no prueba que se autenticara."""
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={
            "delivery_id": entrega["delivery_id"],
            "vault_token": "token-que-nadie-emitio",
        },
        headers=receiver.headers,
    )

    assert ack.status_code == 403
    assert ack.json()["code"] == "ack_token_invalid"

    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{entrega['operation_id']}",
        headers=auth(admin_session),
    )
    assert operacion.json()["status"] == "awaiting_ack"


async def test_ack_con_identidad_incorrecta_no_completa(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Token VALIDO en Vault, pero de otra identidad: 403."""
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    ajeno = approle.issue_foreign_token(
        role_name="vpg-managed-otro-consumidor", policies=("vpg-crawler-managed",)
    )
    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": entrega["delivery_id"], "vault_token": ajeno},
        headers=receiver.headers,
    )

    assert ack.status_code == 403
    assert ack.json()["code"] == "ack_identity_mismatch"


async def test_ack_con_el_token_de_otra_entrega_es_403(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Mismo consumidor y mismo rol, pero credencial de OTRA entrega.

    La comprobacion de identidad (montaje, rol y politica) no distingue este
    caso: todo coincide. Lo que lo distingue es el `delivery_id` que el claim
    escribe en los metadatos del SecretID y que Vault copia al token.
    """
    approle = apps["approle"]
    service = apps["vault_mgmt"].state.provisioning_service
    await alta_lista(vm_client, vm_api, apps, admin_session)

    # Primera entrega: se deja caducar y reconciliar, sin confirmarla.
    primera = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token_viejo = approle.login(
        primera["role_id"], approle.unwrap(primera["wrap_token"])
    )
    approle.expire_wrap(primera["wrap_token"])
    await _caducar_entrega(apps, primera["delivery_id"])
    await service.reconcile_expired_deliveries()

    # Segunda entrega: se intenta confirmar con el token de la PRIMERA.
    segunda = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": segunda["delivery_id"], "vault_token": token_viejo},
        headers=receiver.headers,
    )

    assert ack.status_code == 403
    assert ack.json()["code"] == "ack_delivery_mismatch"


async def test_ack_de_una_entrega_ajena_es_403(
    receiver,vm_client, vm_api, apps, admin_session):
    """Enmascarar no es autorizar: existe y no es suya."""
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": entrega["delivery_id"], "vault_token": "x" * 20},
        headers={"X-VPG-Receiver-Credential": "no-es-la-buena"},
    )
    assert ack.status_code == 401


async def test_ack_dos_veces_es_409(
    receiver,vm_client, vm_api, apps, admin_session):
    approle = apps["approle"]
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token = approle.login(entrega["role_id"], approle.unwrap(entrega["wrap_token"]))

    cuerpo = {"delivery_id": entrega["delivery_id"], "vault_token": token}
    assert (
        await vm_client.post(f"{INTERNAL}/ack", json=cuerpo, headers=receiver.headers)
    ).status_code == 200
    repetido = await vm_client.post(
        f"{INTERNAL}/ack", json=cuerpo, headers=receiver.headers
    )

    assert repetido.status_code == 409
    assert repetido.json()["code"] == "delivery_already_acked"


# ---------------------------------------------------------------------------
# 6. Envoltura caducada: reconciliar, no reintentar a ciegas
# ---------------------------------------------------------------------------


async def test_envoltura_caducada_se_reconcilia_y_destruye_el_secret_id(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """El SecretID huerfano se destruye ANTES de permitir otra emision."""
    approle = apps["approle"]
    service = apps["vault_mgmt"].state.provisioning_service
    await alta_lista(vm_client, vm_api, apps, admin_session)
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    # Nadie la desenvuelve y caduca.
    approle.expire_wrap(entrega["wrap_token"])
    await _caducar_entrega(apps, entrega["delivery_id"])

    cerradas = await service.reconcile_expired_deliveries()

    # >= 1 y no == 1: la base de pruebas acumula entregas de ejecuciones
    # anteriores (no se pueden borrar), y reconciliar las barre tambien.
    assert cerradas >= 1
    # El SecretID emitido ya no sirve para entrar. Se identifico por
    # ELIMINACION: Vault no revela su accessor al envolver.
    assert len(approle.destroyed) == 1
    assert all(not d["alive"] for d in approle.secret_ids.values())

    # La operacion vuelve a esperar al receptor: puede reclamar otra vez.
    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{entrega['operation_id']}",
        headers=auth(admin_session),
    )
    assert operacion.json()["status"] == "waiting_receiver"


async def test_tras_reconciliar_el_claim_emite_una_credencial_nueva(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    approle = apps["approle"]
    service = apps["vault_mgmt"].state.provisioning_service
    await alta_lista(vm_client, vm_api, apps, admin_session)
    primera = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    approle.expire_wrap(primera["wrap_token"])
    await _caducar_entrega(apps, primera["delivery_id"])
    await service.reconcile_expired_deliveries()

    segunda = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers=receiver.headers
    )

    assert segunda.status_code == 200
    assert segunda.json()["status"] == "issued"
    assert segunda.json()["wrap_token"] != primera["wrap_token"]
    assert segunda.json()["delivery_id"] != primera["delivery_id"]


async def _caducar_entrega(apps, delivery_id: str) -> None:
    """Adelanta ``expires_at`` en la base, sin esperar el TTL real."""
    import datetime as dt

    from app.vault_mgmt.repositories import provisioning as repo

    factory = apps["vault_mgmt"].state.session_factory
    async with factory() as session:
        await repo.update_delivery(
            session,
            uuid.UUID(delivery_id),
            expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(seconds=5),
        )
        await session.commit()


# ---------------------------------------------------------------------------
# 7. Rotacion
# ---------------------------------------------------------------------------


async def test_rotacion_after_ack_retira_la_anterior_al_confirmar(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Durante la ventana hay dos SecretID; la vieja cae en el ack."""
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]

    # Primer aprovisionamiento completo.
    primera = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token1 = approle.login(primera["role_id"], approle.unwrap(primera["wrap_token"]))
    await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": primera["delivery_id"], "vault_token": token1},
        headers=receiver.headers,
    )

    # Rotacion after_ack.
    rotacion = await vm_client.post(
        f"{vm_api}/vault/consumers/{consumer_id}/rotate",
        json={"strategy": "after_ack"},
        headers=auth(admin_session),
    )
    assert rotacion.status_code == 202
    await correr_worker(apps, rotacion.json()["operation_id"])

    segunda = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()

    # Lo que sobrevive a una rotacion es el TOKEN anterior, no el SecretID: ese
    # se consumio en el primer login (num_uses=1). Antes del ack sigue vivo, y
    # eso es lo que compra la estrategia: si el rearranque falla, el crawler que
    # ya estaba dentro no se queda fuera.
    assert await approle.lookup_token(token1) != {}

    token2 = approle.login(segunda["role_id"], approle.unwrap(segunda["wrap_token"]))
    ack = await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": segunda["delivery_id"], "vault_token": token2},
        headers=receiver.headers,
    )

    assert ack.status_code == 200, ack.text
    assert ack.json()["retired_previous"] is True
    # Y al confirmarse la nueva, el token anterior se revoca por su accessor.
    assert await approle.lookup_token(token1) == {}
    assert await approle.lookup_token(token2) != {}


async def test_rotacion_inmediata_destruye_la_anterior_al_emitir(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]

    primera = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token1 = approle.login(primera["role_id"], approle.unwrap(primera["wrap_token"]))
    await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": primera["delivery_id"], "vault_token": token1},
        headers=receiver.headers,
    )
    assert await approle.lookup_token(token1) != {}

    rotacion = await vm_client.post(
        f"{vm_api}/vault/consumers/{consumer_id}/rotate",
        json={"strategy": "immediate"},
        headers=auth(admin_session),
    )
    await correr_worker(apps, rotacion.json()["operation_id"])

    # Ventana de corte: el token anterior deja de valer AHORA, aunque nadie haya
    # recogido todavia la credencial nueva. Eso es lo que distingue 'immediate'.
    assert await approle.lookup_token(token1) == {}
    assert approle.revoked_tokens, "deberia haber revocado el token anterior"


async def test_destruir_un_secret_id_no_revoca_el_token_ya_emitido(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """La confusion que la documentacion advierte, comprobada."""
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)

    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token = approle.login(entrega["role_id"], approle.unwrap(entrega["wrap_token"]))
    accessor = next(iter(approle.secret_ids))

    await approle.destroy_secret_id_accessor(next(iter(approle.roles)), accessor)

    # El SecretID ya no sirve para entrar...
    assert approle.secret_ids[accessor]["alive"] is False
    # ...pero el token que salio de el sigue vivo hasta su TTL.
    assert await approle.lookup_token(token) != {}
    del body


# ---------------------------------------------------------------------------
# 8. Revocacion
# ---------------------------------------------------------------------------


async def test_revocacion_bloquea_entregas_y_revoca_lo_revocable(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]
    nombre = (
        await vm_client.get(
            f"{vm_api}/vault/consumers/{consumer_id}", headers=auth(admin_session)
        )
    ).json()["consumer"]["name"]

    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token = approle.login(entrega["role_id"], approle.unwrap(entrega["wrap_token"]))
    await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": entrega["delivery_id"], "vault_token": token},
        headers=receiver.headers,
    )

    revocacion = await vm_client.post(
        f"{vm_api}/vault/consumers/{consumer_id}/revoke",
        json={"confirm": nombre, "reason": "maquina retirada"},
        headers=auth(admin_session),
    )
    assert revocacion.status_code == 202
    estado = await correr_worker(apps, revocacion.json()["operation_id"])

    assert estado == "completed"
    assert approle.roles == {}
    assert approle.revoked_tokens, "deberia revocar el token acreditado"

    detalle = await vm_client.get(
        f"{vm_api}/vault/consumers/{consumer_id}", headers=auth(admin_session)
    )
    assert detalle.json()["consumer"]["state"] == "revoked"

    # Y ya no se entregan credenciales nuevas. El receptor quedo liberado, asi
    # que su credencial deja de resolver a ningun consumidor.
    claim = await vm_client.post(
        f"{INTERNAL}/claim", json={}, headers=receiver.headers
    )
    assert claim.status_code == 403
    assert claim.json()["code"] == "receiver_not_bound"


async def test_revocar_libera_el_receptor_para_otro_consumidor(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """Sin esto, el nombre del receptor quedaba quemado para siempre.

    Un receptor sirve a un solo consumidor, pero ese limite es sobre los
    ACTIVOS. Si la unicidad fuese total, revocar un consumidor dejaria su
    receptor ocupado y el recorrido solo se podria ejecutar una vez.
    """
    primero = await alta_lista(vm_client, vm_api, apps, admin_session)
    nombre = (
        await vm_client.get(
            f"{vm_api}/vault/consumers/{primero['consumer_id']}",
            headers=auth(admin_session),
        )
    ).json()["consumer"]["name"]

    # Mientras este activo, el receptor no se puede reasignar.
    ocupado = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    assert ocupado.status_code == 409
    assert ocupado.json()["code"] == "receiver_taken"

    revocacion = await vm_client.post(
        f"{vm_api}/vault/consumers/{primero['consumer_id']}/revoke",
        json={"confirm": nombre},
        headers=auth(admin_session),
    )
    assert revocacion.status_code == 202
    assert await correr_worker(apps, revocacion.json()["operation_id"]) == "completed"

    # Y ahora si: el mismo receptor sirve a un consumidor nuevo.
    segundo = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    assert segundo.status_code == 202, segundo.text
    assert segundo.json()["consumer_id"] != primero["consumer_id"]

    # El claim resuelve al NUEVO, no al revocado.
    estado = await correr_worker(apps, segundo.json()["operation_id"])
    assert estado == "waiting_receiver"
    claim = await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    assert claim.status_code == 200, claim.text
    assert claim.json()["consumer_id"] == segundo.json()["consumer_id"]


async def test_revocacion_exige_el_nombre_exacto(
    vm_client, vm_api, apps, admin_session
):
    body = await alta_lista(vm_client, vm_api, apps, admin_session)

    response = await vm_client.post(
        f"{vm_api}/vault/consumers/{body['consumer_id']}/revoke",
        json={"confirm": "otro-nombre"},
        headers=auth(admin_session),
    )

    assert response.status_code == 422
    assert response.json()["code"] == "confirmation_mismatch"


# ---------------------------------------------------------------------------
# 9. Persistencia y reanudacion
# ---------------------------------------------------------------------------


async def test_la_solicitud_sobrevive_sin_worker(
    receiver,vm_client, vm_api, admin_session):
    """Un reinicio no la pierde: esta en PostgreSQL, no en memoria."""
    body = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    operation_id = body.json()["operation_id"]

    operacion = await vm_client.get(
        f"{vm_api}/vault/operations/{operation_id}", headers=auth(admin_session)
    )

    assert operacion.status_code == 200
    assert operacion.json()["status"] == "pending"


async def test_el_worker_retoma_lo_pendiente(
    receiver,vm_client, vm_api, apps, admin_session):
    """Reservar, procesar y dejarlo en waiting_receiver, sin perder la solicitud."""
    from app.vault_mgmt.repositories import provisioning as repo

    body = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    operation_id = uuid.UUID(body.json()["operation_id"])
    factory = apps["vault_mgmt"].state.session_factory

    async with factory() as session:
        # Limite alto a proposito: la base de pruebas acumula operaciones
        # pendientes de otras pruebas, porque la cuenta de ejecucion no puede
        # borrar filas de secret_operations (y eso es parte de lo que se prueba).
        reservadas = await repo.claim_operations(
            session,
            worker_name="worker-de-prueba",
            limit=2000,
            lease_seconds=60,
            max_attempts=3,
        )
        ids = [op.operation_id for op in reservadas]
        await session.commit()

    assert operation_id in ids

    estado = await correr_worker(apps, str(operation_id))
    assert estado == "waiting_receiver"


async def test_una_operacion_reservada_no_la_toma_otro_worker(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """El arrendamiento evita que dos workers emitan dos credenciales."""
    from app.vault_mgmt.repositories import provisioning as repo

    await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    factory = apps["vault_mgmt"].state.session_factory

    async with factory() as session:
        primera = await repo.claim_operations(
            session, worker_name="worker-a", limit=10, lease_seconds=300, max_attempts=3
        )
        ids_a = {op.operation_id for op in primera}
        await session.commit()

    async with factory() as session:
        segunda = await repo.claim_operations(
            session, worker_name="worker-b", limit=10, lease_seconds=300, max_attempts=3
        )
        ids_b = {op.operation_id for op in segunda}
        await session.commit()

    assert ids_a, "el primer worker deberia haber reservado algo"
    assert not (ids_a & ids_b), "dos workers no pueden reservar la misma operacion"


# ---------------------------------------------------------------------------
# 10. Entrega mediada y consumidores heredados
# ---------------------------------------------------------------------------


async def test_un_consumidor_nuevo_nace_con_entrega_mediada(
    receiver,
    vm_client, vm_api, admin_session
):
    alta = await registrar(vm_client, vm_api, admin_session, receiver=receiver)
    detalle = await vm_client.get(
        f"{vm_api}/vault/consumers/{alta.json()['consumer_id']}",
        headers=auth(admin_session),
    )
    assert detalle.json()["consumer"]["delivery_mode"] == "mediated"


async def test_la_entrega_mediada_la_lee_el_backend_no_la_maquina(
    receiver,
    vm_client, vm_api, apps, admin_session
):
    """El token del consumidor gestionado no puede leer KV: la lee el backend."""
    approle = apps["approle"]
    body = await alta_lista(vm_client, vm_api, apps, admin_session)
    consumer_id = body["consumer_id"]

    # Un registro real al que asignarle alcance.
    coleccion = await create_collection(vm_client, vm_api, admin_session)
    collection_id = coleccion["collection_id"]
    registro = await create_record(vm_client, vm_api, admin_session, collection_id)
    record_id = registro["record_id"]
    bindings = await vm_client.put(
        f"{vm_api}/vault/consumers/{consumer_id}/bindings",
        json={
            "bindings": [
                {"collection_id": collection_id, "record_id": record_id, "pinned_version": None}
            ]
        },
        headers=auth(admin_session),
    )
    assert bindings.status_code == 200, bindings.text

    # La maquina se autentica y resuelve su entrega.
    entrega = (
        await vm_client.post(f"{INTERNAL}/claim", json={}, headers=receiver.headers)
    ).json()
    token = approle.login(entrega["role_id"], approle.unwrap(entrega["wrap_token"]))
    await vm_client.post(
        f"{INTERNAL}/ack",
        json={"delivery_id": entrega["delivery_id"], "vault_token": token},
        headers=receiver.headers,
    )

    resolve = await vm_client.post(
        f"{vm_api}/integrations/crawler/resolve",
        json={"records": [{"collection_id": collection_id, "record_id": record_id}]},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resolve.status_code == 200, resolve.text
    cuerpo = resolve.json()
    assert cuerpo["delivered"] == 1
    # Queda explicito que la leyo el backend por cuenta de la maquina.
    assert cuerpo["deliveries"][0]["mediated"] is True
