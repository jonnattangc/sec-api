try:
    import logging
    import os
    from functools import wraps
    from flask import Blueprint, request, jsonify
    from flask_jwt_extended import verify_jwt_in_request, get_jwt, get_jwt_identity
    from admin import Admin, USER_ROLES, USER_STATUS, SYSTEM_STATUS, CONTRACT_STATUS

except ImportError as e:
    logging.error(e)
    raise

logger = logging.getLogger('HTTP')

CONTEXT_PATH : str = os.environ.get('CONTEXT_PATH', '/oauth')
# La administración cuelga siempre de CONTEXT_PATH: no tiene variable propia.
ADMIN_CONTEXT_PATH : str = f"{CONTEXT_PATH}/admin"
# Tenant dueño de la plataforma: sus usuarios ADMIN son super-admins.
PLATFORM_TENANT_ID : str = os.environ.get('PLATFORM_TENANT_ID', None)

admin_bp = Blueprint('admin', __name__, url_prefix=ADMIN_CONTEXT_PATH)
public_bp = Blueprint('public', __name__, url_prefix=CONTEXT_PATH)


# ===============================================================================
# Autorización
# ===============================================================================
def _is_superadmin(claims: dict) -> bool :
    """Super-admin = rol SUPERADMIN **y** pertenecer al tenant plataforma. Se exigen las
    dos condiciones a propósito: el rol por sí solo permitiría a un tenant-admin escalar
    creando un SUPERADMIN dentro de su propio tenant."""
    return (str(claims.get('role', '')).lower() == 'superadmin'
            and PLATFORM_TENANT_ID != None
            and str(claims.get('tenant')) == str(PLATFORM_TENANT_ID))


def admin_required(fn):
    """Exige un JWT válido con rol ADMIN o SUPERADMIN (el super-admin hereda al admin)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if str(claims.get('role', '')).lower() not in ('admin', 'superadmin'):
            logger.error(f"Acceso admin denegado para rol: {claims.get('role')}")
            return jsonify({"message": "Requiere rol ADMIN"}), 403
        return fn(*args, **kwargs)
    return wrapper


def superadmin_required(fn):
    """Exige un JWT válido de super-admin (ADMIN del tenant plataforma)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if not _is_superadmin(claims):
            logger.error(f"Acceso super-admin denegado: role={claims.get('role')} tenant={claims.get('tenant')}")
            return jsonify({"message": "Requiere super-admin"}), 403
        return fn(*args, **kwargs)
    return wrapper


def _check_role_grant(claims: dict, role: str) :
    """Solo un super-admin puede otorgar el rol SUPERADMIN. Sin esto un tenant-admin
    podría auto-promoverse creando/editando un usuario de su propio tenant."""
    if str(role).lower() == 'superadmin' and not _is_superadmin(claims) :
        logger.error(f"Intento de otorgar SUPERADMIN por rol={claims.get('role')} tenant={claims.get('tenant')}")
        return jsonify({"message": "Solo un super-admin puede asignar el rol SUPERADMIN"}), 403
    return None


def _body() -> dict :
    return request.get_json(silent=True) or {}


def _is_int(value) -> bool :
    try :
        int(value)
        return True
    except (TypeError, ValueError) :
        return False


# ===============================================================================
# Público / Onboarding (sin auth)
# ===============================================================================
@public_bp.get("/catalog")
def catalog():
    """
    Catálogo de sistemas SaaS contratables
    ---
    tags:
      - Onboarding
    responses:
      200:
        description: Lista de sistemas disponibles (visibles y habilitados)
    """
    adm = Admin()
    systems = [{"name": s["name"],
                "uuid": s["uuid"],
                "description": s.get("description"),
                "order": s.get("order"),
                "url": s.get("url")}
               for s in adm.list_systems()
               if s.get("visible") and str(s.get("status")) == 'ENABLED']
    systems.sort(key=lambda s: (s["order"] is None, s["order"] or 0, s["name"]))
    del adm
    return jsonify({"systems": systems}), 200


@public_bp.post("/my-tenants")
def my_tenants():
    """
    Empresas (tenants) donde el usuario tiene cuenta activa
    ---
    tags:
      - Onboarding
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [username]
            properties:
              username: {type: string, example: "jonnattan"}
    responses:
      200:
        description: Lista de tenants ({name_company, client_id}) para elegir en el login
      400:
        description: Falta el username
    """
    data = _body()
    username = data.get("username") or data.get("email")
    if not username:
        return jsonify({"message": "Falta 'username'"}), 400
    adm = Admin()
    rows = adm.tenants_for_username(username)
    del adm
    tenants = [{"name_company": r["name_company"], "client_id": r["uuid"]} for r in rows]
    return jsonify({"tenants": tenants}), 200


@public_bp.post("/register")
def register():
    """
    Alta self-service de un nuevo cliente (contratar un SaaS)
    ---
    tags:
      - Onboarding
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/RegisterRequest'
    responses:
      201:
        description: Cliente creado (tenant + contrato DEMO + usuario ADMIN)
      400:
        description: Datos incompletos
      404:
        description: Sistema no disponible
      409:
        description: El usuario ya existe
    """
    logger.info(f"INIT: {CONTEXT_PATH}/register... ")
    data = _body()
    system_uuid = data.get("system_uuid")
    company = data.get("company") or {}
    admin_user = data.get("user") or {}

    if not system_uuid or not company.get("name_company") \
            or not admin_user.get("username") or not admin_user.get("password"):
        return jsonify({"message": "Faltan datos: system_uuid, company.name_company, user.username, user.password"}), 400

    adm = Admin()
    system = adm.get_system(system_uuid)          # valida ENABLED
    if system == None :
        del adm
        return jsonify({"message": "Sistema no disponible"}), 404

    result = adm.register(system, company, admin_user)
    del adm
    if result == None :
        return jsonify({"message": "No se pudo completar el registro"}), 400

    return jsonify({
        "message": "Registro exitoso",
        "client_id": result["tenant"]["uuid"],   # cabecera client-id para el login
        "x_api_key": result["system"]["uuid"],    # cabecera x-api-key para el login
        "user": result["user"]
    }), 201


# ===============================================================================
# Administración de Sistemas SaaS (solo super-admin)
# ===============================================================================
@admin_bp.post("/systems")
@superadmin_required
def create_system():
    """
    Crear sistema SaaS
    ---
    tags: [Administración - Sistemas]
    security: [BearerAuth: []]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [name]
            properties:
              name:        {type: string, example: "Portal de Firmas"}
              visible:     {type: integer, example: 1}
              status:      {type: string, enum: [ENABLED, DISABLED], example: "ENABLED"}
              description: {type: string, example: "Firma electrónica de contratos"}
              url:         {type: string, example: "https://firmas.jonna.cl"}
              order:       {type: integer, example: 10}
    responses:
      201: {description: Sistema creado}
      400: {description: Datos inválidos}
      403: {description: Requiere super-admin}
    """
    data = _body()
    if not data.get("name"):
        return jsonify({"message": "Falta 'name'"}), 400
    status = data.get("status", 'ENABLED')
    if status not in SYSTEM_STATUS:
        return jsonify({"message": f"status inválido, use {SYSTEM_STATUS}"}), 400
    order = data.get("order")
    if order is not None and not _is_int(order):
        return jsonify({"message": "'order' debe ser un número entero"}), 400
    adm = Admin()
    system = adm.create_system(data["name"], data.get("visible", 1), status,
                               data.get("description"), data.get("url"),
                               int(order) if order is not None else None)
    del adm
    return (jsonify(system), 201) if system else (jsonify({"message": "No se pudo crear"}), 400)


@admin_bp.get("/systems")
@superadmin_required
def list_systems():
    """
    Listar sistemas SaaS
    ---
    tags: [Administración - Sistemas]
    security: [BearerAuth: []]
    responses:
      200: {description: Lista de sistemas}
    """
    adm = Admin()
    data = adm.list_systems()
    del adm
    return jsonify({"systems": data}), 200


@admin_bp.get("/systems/<int:system_id>")
@superadmin_required
def get_system(system_id):
    """
    Obtener sistema por id
    ---
    tags: [Administración - Sistemas]
    security: [BearerAuth: []]
    responses:
      200: {description: Sistema}
      404: {description: No encontrado}
    """
    adm = Admin()
    system = adm.get_system_by_id(system_id)
    del adm
    return (jsonify(system), 200) if system else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.put("/systems/<int:system_id>")
@superadmin_required
def update_system(system_id):
    """
    Actualizar sistema
    ---
    tags: [Administración - Sistemas]
    security: [BearerAuth: []]
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              name:        {type: string, example: "Portal de Firmas"}
              visible:     {type: integer, example: 1}
              status:      {type: string, enum: [ENABLED, DISABLED], example: "ENABLED"}
              description: {type: string, example: "Firma electrónica de contratos"}
              url:         {type: string, example: "https://firmas.jonna.cl"}
              order:       {type: integer, example: 10}
    responses:
      200: {description: Sistema actualizado}
      400: {description: Datos inválidos}
      404: {description: No encontrado}
    """
    data = _body()
    if data.get("status") and data["status"] not in SYSTEM_STATUS:
        return jsonify({"message": f"status inválido, use {SYSTEM_STATUS}"}), 400
    if data.get("order") is not None and not _is_int(data["order"]):
        return jsonify({"message": "'order' debe ser un número entero"}), 400
    adm = Admin()
    system = adm.update_system(system_id, data)
    del adm
    return (jsonify(system), 200) if system else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.delete("/systems/<int:system_id>")
@superadmin_required
def delete_system(system_id):
    """
    Deshabilitar sistema (baja lógica -> DISABLED)
    ---
    tags: [Administración - Sistemas]
    security: [BearerAuth: []]
    responses:
      200: {description: Sistema deshabilitado}
    """
    adm = Admin()
    ok = adm.disable_system(system_id)
    del adm
    return (jsonify({"message": "Sistema deshabilitado"}), 200) if ok else (jsonify({"message": "No encontrado"}), 404)


# ===============================================================================
# Administración de Tenants (solo super-admin)
# ===============================================================================
@admin_bp.post("/tenants")
@superadmin_required
def create_tenant():
    """
    Crear tenant/cliente
    ---
    tags: [Administración - Tenants]
    security: [BearerAuth: []]
    responses:
      201: {description: Tenant creado}
      400: {description: Datos inválidos}
    """
    data = _body()
    if not data.get("name_company"):
        return jsonify({"message": "Falta 'name_company'"}), 400
    adm = Admin()
    tenant = adm.create_tenant(data["name_company"], data.get("razon_social"),
                               data.get("contacto"), data.get("mail_contacto"))
    del adm
    return (jsonify(tenant), 201) if tenant else (jsonify({"message": "No se pudo crear"}), 400)


@admin_bp.get("/tenants")
@superadmin_required
def list_tenants():
    """
    Listar tenants
    ---
    tags: [Administración - Tenants]
    security: [BearerAuth: []]
    responses:
      200: {description: Lista de tenants}
    """
    adm = Admin()
    data = adm.list_tenants()
    del adm
    return jsonify({"tenants": data}), 200


@admin_bp.get("/tenants/<int:tenant_id>")
@superadmin_required
def get_tenant(tenant_id):
    """
    Obtener tenant por id
    ---
    tags: [Administración - Tenants]
    security: [BearerAuth: []]
    responses:
      200: {description: Tenant}
      404: {description: No encontrado}
    """
    adm = Admin()
    tenant = adm.get_tenant_by_id(tenant_id)
    del adm
    return (jsonify(tenant), 200) if tenant else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.put("/tenants/<int:tenant_id>")
@superadmin_required
def update_tenant(tenant_id):
    """
    Actualizar tenant
    ---
    tags: [Administración - Tenants]
    security: [BearerAuth: []]
    responses:
      200: {description: Tenant actualizado}
      404: {description: No encontrado}
    """
    adm = Admin()
    tenant = adm.update_tenant(tenant_id, _body())
    del adm
    return (jsonify(tenant), 200) if tenant else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.delete("/tenants/<int:tenant_id>")
@superadmin_required
def delete_tenant(tenant_id):
    """
    Eliminar tenant (cascada: desactiva contratos y usuarios, revoca tokens)
    ---
    tags: [Administración - Tenants]
    security: [BearerAuth: []]
    responses:
      200: {description: Tenant eliminado}
      404: {description: No encontrado}
    """
    adm = Admin()
    ok = adm.delete_tenant(tenant_id)
    del adm
    return (jsonify({"message": "Tenant eliminado"}), 200) if ok else (jsonify({"message": "No encontrado"}), 404)


# ===============================================================================
# Administración de Contratos (solo super-admin)
# ===============================================================================
@admin_bp.post("/contracts")
@superadmin_required
def create_contract():
    """
    Crear contrato tenant-sistema
    ---
    tags: [Administración - Contratos]
    security: [BearerAuth: []]
    responses:
      201: {description: Contrato creado}
      400: {description: Datos inválidos}
    """
    data = _body()
    if not data.get("tenant_id") or not data.get("system_id"):
        return jsonify({"message": "Faltan 'tenant_id' y/o 'system_id'"}), 400
    status = data.get("status", 'DEMO')
    if status not in CONTRACT_STATUS:
        return jsonify({"message": f"status inválido, use {CONTRACT_STATUS}"}), 400
    adm = Admin()
    contract = adm.create_contract(data["tenant_id"], data["system_id"], status, data.get("finish_at"))
    del adm
    return (jsonify(contract), 201) if contract else (jsonify({"message": "No se pudo crear"}), 400)


@admin_bp.get("/contracts")
@superadmin_required
def list_contracts():
    """
    Listar contratos (filtro opcional ?tenant_id=)
    ---
    tags: [Administración - Contratos]
    security: [BearerAuth: []]
    responses:
      200: {description: Lista de contratos}
    """
    adm = Admin()
    data = adm.list_contracts(request.args.get("tenant_id"))
    del adm
    return jsonify({"contracts": data}), 200


@admin_bp.get("/contracts/<int:contract_id>")
@superadmin_required
def get_contract(contract_id):
    """
    Obtener contrato por id
    ---
    tags: [Administración - Contratos]
    security: [BearerAuth: []]
    responses:
      200: {description: Contrato}
      404: {description: No encontrado}
    """
    adm = Admin()
    contract = adm.get_contract_by_id(contract_id)
    del adm
    return (jsonify(contract), 200) if contract else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.put("/contracts/<int:contract_id>")
@superadmin_required
def update_contract(contract_id):
    """
    Actualizar contrato (estado / finish_at)
    ---
    tags: [Administración - Contratos]
    security: [BearerAuth: []]
    responses:
      200: {description: Contrato actualizado}
      400: {description: Datos inválidos}
    """
    data = _body()
    if data.get("status") and data["status"] not in CONTRACT_STATUS:
        return jsonify({"message": f"status inválido, use {CONTRACT_STATUS}"}), 400
    adm = Admin()
    contract = adm.update_contract(contract_id, data)
    del adm
    return (jsonify(contract), 200) if contract else (jsonify({"message": "No encontrado"}), 404)


@admin_bp.delete("/contracts/<int:contract_id>")
@superadmin_required
def delete_contract(contract_id):
    """
    Desactivar contrato (baja lógica -> INACTIVE)
    ---
    tags: [Administración - Contratos]
    security: [BearerAuth: []]
    responses:
      200: {description: Contrato desactivado}
    """
    adm = Admin()
    ok = adm.deactivate_contract(contract_id)
    del adm
    return (jsonify({"message": "Contrato desactivado"}), 200) if ok else (jsonify({"message": "No encontrado"}), 404)


# ===============================================================================
# Administración de Usuarios (ADMIN, con aislamiento por tenant)
# ===============================================================================
def _owns_user(adm: Admin, user: dict, claims: dict) -> bool :
    """Indica si el usuario objetivo pertenece al tenant del token. `user['tenant_id']` es
    el id numérico y el claim `tenant` es el uuid, por eso se resuelve antes de comparar."""
    own_id = adm.resolve_tenant_id(claims.get("tenant"))
    return own_id != None and str(user.get("tenant_id")) == str(own_id)


def _effective_tenant(claims: dict, requested_tenant_id):
    """Devuelve (tenant_id, error_response). Un super-admin puede operar sobre el tenant
    solicitado; un tenant-admin queda forzado a su propio tenant."""
    if _is_superadmin(claims):
        if requested_tenant_id in (None, ""):
            return None, (jsonify({"message": "super-admin debe indicar tenant_id"}), 400)
        return requested_tenant_id, None
    own = claims.get("tenant")
    if requested_tenant_id not in (None, "") and str(requested_tenant_id) != str(own):
        return None, (jsonify({"message": "No autorizado para ese tenant"}), 403)
    return own, None


@admin_bp.post("/users")
@admin_required
def create_user():
    """
    Crear usuario
    ---
    tags: [Administración - Usuarios]
    security: [BearerAuth: []]
    responses:
      201: {description: Usuario creado}
      400: {description: Datos inválidos}
      403: {description: Tenant no autorizado}
      409: {description: Usuario ya existe}
    """
    claims = get_jwt()
    data = _body()
    tenant_id, err = _effective_tenant(claims, data.get("tenant_id"))
    if err:
        return err
    if not data.get("username") or not data.get("password"):
        return jsonify({"message": "Faltan 'username' y/o 'password'"}), 400
    role = data.get("role", 'USER')
    if role not in USER_ROLES:
        return jsonify({"message": f"role inválido, use {USER_ROLES}"}), 400
    if err := _check_role_grant(claims, role):
        return err
    status = data.get("status", 'ACTIVE')
    if status not in USER_STATUS:
        return jsonify({"message": f"status inválido, use {USER_STATUS}"}), 400
    adm = Admin()
    if adm.user_in_tenant(tenant_id, data["username"]) != None:
        del adm
        return jsonify({"message": "El usuario ya existe en el tenant"}), 409
    user = adm.create_user(tenant_id, data["username"], data["password"], role,
                           data.get("claims"), data.get("full_name"), status)
    del adm
    return (jsonify(user), 201) if user else (jsonify({"message": "No se pudo crear"}), 400)


@admin_bp.get("/users")
@admin_required
def list_users():
    """
    Listar usuarios del tenant (super-admin: ?tenant_id= requerido)
    ---
    tags: [Administración - Usuarios]
    security: [BearerAuth: []]
    responses:
      200: {description: Lista de usuarios}
    """
    claims = get_jwt()
    tenant_id, err = _effective_tenant(claims, request.args.get("tenant_id"))
    if err:
        return err
    adm = Admin()
    data = adm.list_users(tenant_id)
    del adm
    return jsonify({"users": data}), 200


@admin_bp.get("/users/<int:user_id>")
@admin_required
def get_user(user_id):
    """
    Obtener usuario por id
    ---
    tags: [Administración - Usuarios]
    security: [BearerAuth: []]
    responses:
      200: {description: Usuario}
      403: {description: Tenant no autorizado}
      404: {description: No encontrado}
    """
    claims = get_jwt()
    adm = Admin()
    user = adm.get_user_by_id(user_id)
    if user == None:
        del adm
        return jsonify({"message": "No encontrado"}), 404
    if not _is_superadmin(claims) and not _owns_user(adm, user, claims):
        del adm
        return jsonify({"message": "No autorizado para ese tenant"}), 403
    result = adm.clean_user(user)
    del adm
    return jsonify(result), 200


@admin_bp.put("/users/<int:user_id>")
@admin_required
def update_user(user_id):
    """
    Actualizar usuario (role, status, full_name, claims, reset password)
    ---
    tags: [Administración - Usuarios]
    security: [BearerAuth: []]
    responses:
      200: {description: Usuario actualizado}
      400: {description: Datos inválidos}
      403: {description: Tenant no autorizado}
      404: {description: No encontrado}
    """
    claims = get_jwt()
    data = _body()
    if data.get("role") and data["role"] not in USER_ROLES:
        return jsonify({"message": f"role inválido, use {USER_ROLES}"}), 400
    if data.get("role") and (err := _check_role_grant(claims, data["role"])):
        return err
    if data.get("status") and data["status"] not in USER_STATUS:
        return jsonify({"message": f"status inválido, use {USER_STATUS}"}), 400
    adm = Admin()
    user = adm.get_user_by_id(user_id)
    if user == None:
        del adm
        return jsonify({"message": "No encontrado"}), 404
    if not _is_superadmin(claims) and not _owns_user(adm, user, claims):
        del adm
        return jsonify({"message": "No autorizado para ese tenant"}), 403
    updated = adm.update_user(user_id, data)
    del adm
    return (jsonify(updated), 200) if updated else (jsonify({"message": "No se pudo actualizar"}), 400)


@admin_bp.delete("/users/<int:user_id>")
@admin_required
def delete_user(user_id):
    """
    Eliminar usuario (baja lógica -> INACTIVE + revoca tokens)
    ---
    tags: [Administración - Usuarios]
    security: [BearerAuth: []]
    responses:
      200: {description: Usuario desactivado}
      403: {description: Tenant no autorizado}
      404: {description: No encontrado}
    """
    claims = get_jwt()
    adm = Admin()
    user = adm.get_user_by_id(user_id)
    if user == None:
        del adm
        return jsonify({"message": "No encontrado"}), 404
    if not _is_superadmin(claims) and not _owns_user(adm, user, claims):
        del adm
        return jsonify({"message": "No autorizado para ese tenant"}), 403
    ok = adm.deactivate_user(user_id)
    del adm
    return (jsonify({"message": "Usuario desactivado"}), 200) if ok else (jsonify({"message": "No se pudo eliminar"}), 400)
