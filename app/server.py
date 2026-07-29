#!/usr/bin/python

try:
    import logging
    import sys
    import os
    import time
    import ipaddress
    from datetime import datetime, timedelta
    from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, decode_token
    from flask import Flask, request, jsonify
    from werkzeug.middleware.proxy_fix import ProxyFix
    from flasgger import Swagger
    from flask_cors import CORS
    from security import Security
    from routes import admin_bp, public_bp

except ImportError:

    logging.error(ImportError)
    print((os.linesep * 2).join(['[http-server] Error al buscar los modulos:',
                                 str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)


############################# Configuraci'on de Registro de Log  ################################
FORMAT = '%(asctime)s %(levelname)s : %(message)s'
root = logging.getLogger()
root.setLevel(logging.INFO)
formatter = logging.Formatter(FORMAT)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
root.addHandler(handler)
logger = logging.getLogger('HTTP')

# ===============================================================================
# variables globales
# ===============================================================================
ROOT_DIR = os.path.dirname(__file__)

EXPIRES_IN_SECONDS : int = int(os.environ.get('EXPIRES_TOKEN_IN_SECONDS', 300 ))
# Vida del refresh token. Debe ir alineada con Security.REFRESH_EXPIRES_DAYS, que purga
# de user_jwt las sesiones que ya no pueden renovarse.
REFRESH_EXPIRES_IN_DAYS : int = int(os.environ.get('REFRESH_EXPIRES_IN_DAYS', 30))
SECRET_JWT : str = os.environ.get('SECRET_KEY_JWT','super-secret-key-aca-debe-ir')

# Cabecera con la que el consumidor declara desde dónde se abre la sesión. Permite que
# un mismo usuario esté conectado a la vez en la consola web y en la aplicación móvil.
CHANNEL_HEADER : str = 'x-channel'

CONTEXT_PATH : str = os.environ.get('CONTEXT_PATH','/oauth')

DEFAULT_CORS_ORIGINS = "https://dev.jonnattan.com,https://api.jonnatech.cl,https://www.jonnatech.cl,https://api.jonnattan.cl,https://www.jonna.cl,https://www.jonnattan.cl,https://api.jonna.cl,https://docs.jonna.cl,https://docs.jonnattan.cl"
CORS_ORIGINS : list = [origin.strip() for origin in os.environ.get('CORS_ORIGINS', DEFAULT_CORS_ORIGINS).split(',') if origin.strip()]

# ------------------------------------------------------- Restricción por red de origen
# Redes autorizadas (CIDR, separadas por coma): red local + rango de pods del cluster.
# Vacío = filtro DESACTIVADO (la API queda abierta); se avisa por log al arrancar.
ALLOWED_NETWORKS : list = []
for _cidr in os.environ.get('ALLOWED_NETWORKS', '').split(',') :
    _cidr = _cidr.strip()
    if _cidr :
        try :
            ALLOWED_NETWORKS.append(ipaddress.ip_network(_cidr, strict=False))
        except ValueError as e :
            print(f"ERROR ALLOWED_NETWORKS: CIDR inválido '{_cidr}': {e}")

# Nº de reverse proxies de confianza delante de la app (ingress, nginx...).
# 0 = la app recibe conexiones directas y se usa la IP del peer TCP.
# >0 = se toma la IP del cliente desde X-Forwarded-For saltando N saltos confiables.
# Debe coincidir EXACTAMENTE con la infra: si es menor que los proxies reales, un
# cliente puede falsear su IP mandando su propia cabecera X-Forwarded-For.
TRUSTED_PROXY_COUNT : int = int(os.environ.get('TRUSTED_PROXY_COUNT', 0))

# Rutas exentas del filtro. Vacío por defecto: el tráfico es backend-a-backend, ningún
# navegador llega directo a esta API, así que no hay motivo para dejar rutas abiertas.
PUBLIC_PATHS : tuple = tuple(p.strip() for p in os.environ.get('PUBLIC_PATHS', '').split(',') if p.strip())

# Health check. Exento del filtro de red: las probes de Kubernetes llegan desde la IP del
# nodo (kubelet), que normalmente no está en ALLOWED_NETWORKS. No expone datos sensibles.
HEALTH_PATH : str = f"{CONTEXT_PATH}/health"

app = Flask(__name__, static_url_path=f"{CONTEXT_PATH}/static")

# x_for hace que request.remote_addr sea la IP real del cliente cuando hay proxies
# de confianza delante. Con TRUSTED_PROXY_COUNT=0, remote_addr es el peer TCP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=TRUSTED_PROXY_COUNT)

template = {
    "openapi": "3.0.1",
    "info": {
        "title": "API de Seguridad OAuth2/JWT",
        "description": "Servidor de autenticación centralizado con JWT para servicios internos",
        "version": "1.0.0",
        "contact": {
            "name": "Soporte",
            "email": "jonnattan@gmail.com"
        }
    },
    "servers": [
        {
            "url": "http://localhost:8079",
            "description": "Servidor local de desarrollo"
        }
    ],
    "components": {
        "schemas": {
            "LoginRequest": {
                "type": "object",
                "required": ["username", "password"],
                "properties": {
                    "username": {
                        "type": "string",
                        "example": "usuario"
                    },
                    "password": {
                        "type": "string",
                        "example": "contraseña_segura"
                    }
                }
            },
            "User": {
                "type": "object",
                "description": "Usuario (tabla oauth). El id, uuid y tenant_id se omiten en la respuesta.",
                "properties": {
                    "username": {
                        "type": "string",
                        "example": "usuario"
                    },
                    "full_name": {
                        "type": "string",
                        "example": "Nombre Real"
                    },
                    "role": {
                        "type": "string",
                        "enum": ["SUPERADMIN", "ADMIN", "USER", "QUERY"],
                        "example": "USER"
                    },
                    "claims": {
                        "type": "string",
                        "example": "RW"
                    },
                    "status": {
                        "type": "string",
                        "example": "ACTIVE"
                    },
                    "last_login": {
                        "type": "string",
                        "format": "date-time",
                        "example": "2026-04-19T10:30:00"
                    }
                }
            },
            "Client": {
                "type": "object",
                "description": "Cliente/tenant (tabla tenant). El id y uuid se omiten en la respuesta.",
                "properties": {
                    "name_company": {
                        "type": "string",
                        "example": "Mi Empresa"
                    },
                    "razon_social": {
                        "type": "string",
                        "example": "Mi Empresa S.A."
                    },
                    "contacto": {
                        "type": "string",
                        "example": "Juan Pérez"
                    },
                    "mail_contacto": {
                        "type": "string",
                        "example": "contacto@miempresa.com"
                    }
                }
            },
            "System": {
                "type": "object",
                "description": "Sistema SaaS (tabla saas_system). El id, uuid y status se omiten en la respuesta.",
                "properties": {
                    "name": {
                        "type": "string",
                        "example": "notification"
                    },
                    "visible": {
                        "type": "integer",
                        "example": 1
                    }
                }
            },
            "LoginResponse": {
                "type": "object",
                "properties": {
                    "access_token": {
                        "type": "string",
                        "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    },
                    "refresh_token": {
                        "type": "string",
                        "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    },
                    "user": {
                        "$ref": "#/components/schemas/User"
                    },
                    "client": {
                        "$ref": "#/components/schemas/Client"
                    },
                    "system": {
                        "$ref": "#/components/schemas/System"
                    }
                }
            },
            "RegisterRequest": {
                "type": "object",
                "required": ["system_uuid", "company", "user"],
                "properties": {
                    "system_uuid": {
                        "type": "string",
                        "description": "uuid del sistema SaaS a contratar (de /oauth/catalog)",
                        "example": "87ebf297-82c6-11f1-981f-5a08c73ec56b"
                    },
                    "company": {
                        "type": "object",
                        "required": ["name_company"],
                        "properties": {
                            "name_company": {"type": "string", "example": "Mi Empresa"},
                            "razon_social": {"type": "string", "example": "Mi Empresa S.A."},
                            "contacto": {"type": "string", "example": "Juan Pérez"},
                            "mail_contacto": {"type": "string", "example": "contacto@miempresa.com"}
                        }
                    },
                    "user": {
                        "type": "object",
                        "required": ["username", "password"],
                        "properties": {
                            "username": {"type": "string", "example": "admin"},
                            "password": {"type": "string", "example": "contraseña_segura"},
                            "full_name": {"type": "string", "example": "Juan Pérez"},
                            "claims": {"type": "string", "example": "RW"}
                        }
                    }
                }
            },
            "MessageResponse": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "example": "OK"
                    }
                }
            },
            "ErrorResponse": {
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "example": "No autorizado"
                    }
                }
            }
        },
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            },
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "x-api-key"
            }
        }
    }
}



app.config['SWAGGER'] = {
    'title': 'API de Seguridad OAuth2/JWT',
    'uiversion': 3,
    'openapi': '3.0.1',
    'specs_route': f"{CONTEXT_PATH}/apidocs/",
    'doc_dir': str(ROOT_DIR) + '/docs',
    'static_url_path': f"{CONTEXT_PATH}/flasgger_static",
    'oauth_redirect': f"{CONTEXT_PATH}/oauth2-redirect.html",
    'specs': [
        {
            "endpoint": 'api_oauth',
            "route": f"{CONTEXT_PATH}/api_oauth.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "headers": [],
    "schemes": ["https", "http"],
    "static_lib_url": "https://unpkg.com/swagger-ui-dist@3/"
}

swagger = Swagger(app, template=template)

# JWT Manager Config
app.config["JWT_SECRET_KEY"] = SECRET_JWT
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = EXPIRES_IN_SECONDS
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=REFRESH_EXPIRES_IN_DAYS)

jwt = JWTManager(app)

cors = CORS(app, origins=CORS_ORIGINS)

# Blueprints de administración (protegido) y onboarding público
app.register_blueprint(admin_bp)
app.register_blueprint(public_bp)


@app.before_request
def restrict_by_network():
    """Rechaza (403) toda petición que no venga de una red autorizada.

    Se aplica a TODA la API salvo el health check, las rutas de PUBLIC_PATHS (vacío por
    defecto) y el preflight CORS. Si ALLOWED_NETWORKS está vacío el filtro no se aplica."""
    if len(ALLOWED_NETWORKS) == 0 :
        return None
    if request.method == 'OPTIONS' :
        return None
    if request.path == HEALTH_PATH :
        return None
    if request.path in PUBLIC_PATHS :
        return None

    remote = request.remote_addr
    try :
        client_ip = ipaddress.ip_address(remote) if remote else None
    except ValueError :
        client_ip = None

    if client_ip != None :
        for net in ALLOWED_NETWORKS :
            if client_ip in net :
                return None

    logger.warning(f"Acceso denegado a {request.path} desde IP no autorizada: {remote}")
    return jsonify({"message": "Acceso denegado: origen no autorizado"}), 403


def resolve_context(sec):
    """Resuelve el sistema (header x-api-key) y el cliente/tenant (header client-id)
    desde la petición y valida que exista un contrato vigente entre ambos.

    Retorna la tupla (system, tenant, contract). Cualquiera de los elementos será
    None si no se pudo resolver o si el contrato no está vigente."""
    x_api_key : str = request.headers.get('x-api-key', None)
    client_id : str = request.headers.get('client-id', None)

    system : dict = sec.get_system(x_api_key)
    if system == None :
        logger.error(f"Sistema no encontrado o deshabilitado para x-api-key: {x_api_key}")
        return None, None, None

    tenant : dict = sec.get_tenant(client_id)
    if tenant == None :
        logger.error(f"Cliente no encontrado para client-id: {client_id}")
        return system, None, None

    contract : dict = sec.get_active_contract(tenant['id'], system['id'])
    if contract == None :
        logger.error(f"Sin contrato vigente entre tenant[{tenant['id']}] y sistema[{system['id']}]")
        return system, tenant, None

    logger.info(f"Sistema[{system['id']}]={system['name']} | Cliente[{tenant['id']}]={tenant['name_company']} | Contrato[{contract['id']}]={contract['status']}")
    return system, tenant, contract


@app.get(HEALTH_PATH)
def health():
    """
    Health check (liveness/readiness)
    ---
    tags:
      - Operación
    responses:
      200:
        description: Servicio y base de datos operativos
      503:
        description: Base de datos no disponible
    """
    sec = None
    db_ok = False
    detail = None
    try:
        sec = Security()
        if sec.db != None:
            cursor = sec.db.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            db_ok = True
        else:
            detail = "sin conexión a la base de datos"
    except Exception as e:
        detail = str(e)
        logger.error(f"Health check falló: {e}")
    finally:
        if sec != None:
            del sec

    body = {"status": "UP" if db_ok else "DOWN", "database": "UP" if db_ok else "DOWN"}
    if detail != None:
        body["detail"] = detail
    return jsonify(body), (200 if db_ok else 503)


@app.get(f"{CONTEXT_PATH}/validate")
@jwt_required()
def validate():
    """
    Validar Token JWT
    ---
    tags:
      - Autenticación
    security:
      - BearerAuth: []
      - ApiKeyAuth: []
    parameters:
      - in: header
        name: x-api-key
        required: true
        schema:
          type: string
        description: UUID del sistema SaaS (saas_system.uuid)
      - in: header
        name: client-id
        required: true
        schema:
          type: string
        description: UUID del cliente/tenant (tenant.uuid)
    responses:
      200:
        description: Token válido
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MessageResponse'
      401:
        description: Token inválido o no autorizado
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    logger.info(f"INIT: {CONTEXT_PATH}/validate... ")
    data_json = {"message": "Validación fallida"}
    http_status = 401
    sec = Security()

    system, client, contract = resolve_context(sec)
    if system == None or client == None or contract == None :
        del sec
        return jsonify({"message": "No autorizado"}), 401

    http_status = 200
    jwt = get_jwt()
    current_user = get_jwt_identity()
    user = sec.user_exists(current_user, client["id"])

    data_json = {"message": "OK", "client": client, "system": system, "user": user}

    # verificar el cliente/tenant por si fue modificado en el front
    if jwt == None or str(jwt.get("tenant")) != str(client["uuid"]) :
        logger.info(f"Tenant JWT: {jwt.get('tenant') if jwt else None} != {client['uuid']}")
        data_json = {"message": "Cliente y/o usuario no autorizado"}
        http_status = 401
    # verificar el sistema por si fue modificado en el front
    if jwt == None or str(jwt.get("system")) != str(system["uuid"]) :
        logger.info(f"Sistema JWT: {jwt.get('system') if jwt else None} != {system['uuid']}")
        data_json = {"message": "Sistema no autorizado"}
        http_status = 401
    # verificar el rol del usuario por si fue modificado en el front
    if user == None or str(jwt["role"]).lower() != str(user["role"]).lower() :
        logger.info(f"Rol JWT: {jwt['role']} y Rol User: {user['role'] if user else None}")
        data_json = {"message": "Rol o usuario no autorizado"}
        http_status = 401
    # verifico si el token es valido, es decir no se ha caducado por otro lado
    if sec.is_token_valid( jwt ) == False :
        logger.info(f"Token JWT No Valido: {jwt}")
        data_json = {"message": "Token no autorizado"}
        http_status = 401
    # se limpia la data sensible/interna recién al final, tras las validaciones
    clean_data(user, client, system)
    del sec
    return jsonify(data_json), http_status

def clean_data(user : dict, tenant: dict, system: dict ) :
    # se limpia lo que se envia
    try :
        if "password" in user :
            del user["password"]
        if "create_at" in user :
            del user["create_at"]
        if "update_at" in user :
            del user["update_at"]
        if "update_at" in user :
            del user["update_at"]
        if "id" in user :
            del user["id"]
        if "uuid" in user :
            del user["uuid"]
        if "tenant_id" in user :
            del user["tenant_id"]
        if "id" in tenant :
            del tenant["id"]
        if "uuid" in tenant :
            del tenant["uuid"]
        if "id" in system :
            del system["id"]
        if "uuid" in system :
            del system["uuid"]
        if "status" in system :
            del system["status"]
    except :
        pass

@app.post(f"{CONTEXT_PATH}/login")
def login():
    """
    Iniciar Sesión - Obtener Tokens JWT
    ---
    tags:
      - Autenticación
    parameters:
      - in: header
        name: x-api-key
        required: true
        schema:
          type: string
        description: UUID del sistema SaaS (saas_system.uuid)
      - in: header
        name: client-id
        required: true
        schema:
          type: string
        description: UUID del cliente/tenant (tenant.uuid)
    requestBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/LoginRequest'
    responses:
      200:
        description: Autenticación exitosa
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginResponse'
      401:
        description: Credenciales inválidas o cliente no autorizado
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    logger.info(f"INIT: {CONTEXT_PATH}/login... ")
    sec = Security()

    # Regla 1: debe existir un contrato vigente entre el cliente (client-id)
    # y el sistema (x-api-key) para permitir el login.
    system, client, contract = resolve_context(sec)
    if system == None or client == None or contract == None :
        del sec
        return jsonify({"message": "No autorizado"}), 401

    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = sec.verify_credentials(username, password, client)
    del sec
    return process_response_jwt( user, client, system, request_channel() )

@app.get(f"{CONTEXT_PATH}/refresh")
@jwt_required(refresh=True)
def refresh():
    """
    Refrescar Token de Acceso
    ---
    tags:
      - Autenticación
    security:
      - BearerAuth: []
    parameters:
      - in: header
        name: x-api-key
        required: true
        schema:
          type: string
        description: UUID del sistema SaaS (saas_system.uuid)
      - in: header
        name: client-id
        required: true
        schema:
          type: string
        description: UUID del cliente/tenant (tenant.uuid)
      - in: header
        name: Authorization
        required: true
        schema:
          type: string
        description: Refresh token en formato "Bearer {token}"
    responses:
      200:
        description: Token refrescado exitosamente
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginResponse'
      401:
        description: Refresh token inválido o expirado
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    logger.info(f"INIT: {CONTEXT_PATH}/Refresh... ")
    sec = Security()

    # Se revalida el contrato vigente entre cliente y sistema en cada refresh.
    system, client, contract = resolve_context(sec)
    if system == None or client == None or contract == None :
        del sec
        return jsonify({"message": "No autorizado"}), 401

    user_name = get_jwt_identity()
    user = sec.user_exists(user_name, client['id'])
    jwt = get_jwt()
    if jwt == None or str(jwt.get("tenant")) != str(client["uuid"]) :
        logger.info(f"Tenant JWT: {jwt.get('tenant') if jwt else None} != {client['uuid']}")
        del sec
        return jsonify({"message": "Cliente y/o usuario no autorizado"}), 401
    if str(jwt.get("system")) != str(system["uuid"]) :
        logger.info(f"Sistema JWT: {jwt.get('system')} != {system['uuid']}")
        del sec
        return jsonify({"message": "Sistema no autorizado"}), 401
    # verificar el rol del usuario por si fue modificado en el front
    if user == None or str(jwt["role"]).lower() != str(user["role"]).lower()  :
        logger.info(f"Rol JWT: {jwt['role']} y Rol User: {user['role'] if user else None}")
        del sec
        return jsonify({"message": "Rol o usuario no autorizado para el refresh"}), 401
    valid_token = sec.is_refresh_token_valid(jwt)
    if valid_token == False :
        del sec
        return jsonify({"message": "Invalid Refresh Token"}), 401
    # La sesión conserva su canal al rotar los tokens; la fila de user_jwt manda por
    # sobre el claim, para que los tokens emitidos antes de esta versión también roten.
    refresh_id : str = jwt["jti"]
    channel : str = sec.session_channel(refresh_id)
    del sec
    return process_response_jwt( user, client, system, channel, refresh_id )


def request_channel() -> str :
    """Canal declarado por el consumidor en la cabecera x-channel (WEB por omisión).
    Lo envía el backend dueño de la sesión (nunca el navegador): la consola web pide
    WEB y la aplicación móvil MOBILE."""
    channel : str = str(request.headers.get(CHANNEL_HEADER, '')).strip().upper()
    return channel if channel in Security.CHANNELS else Security.DEFAULT_CHANNEL


def process_response_jwt( user : dict, client : dict = None, system : dict = None,
                          channel : str = None, previous_refresh_id : str = None ) :
    if user == None :
        return jsonify({"message": f"usuario inválido"}), 401

    channel = channel if channel in Security.CHANNELS else Security.DEFAULT_CHANNEL
    claims : dict = {
        "tenant" : str(client["uuid"]),
        "system" : str(system["uuid"]) if system != None else None,
        "claims"   : str(user["claims"]).lower(),
        "role"     : str(user["role"]).lower(),
        "channel"  : channel
    }

    username : str = str(user["username"])
    user_id : str = str(user["id"])

    access_token : str = create_access_token(identity=username, additional_claims=claims)
    token_data : dict = decode_token(access_token)
    refresh_token : str = create_refresh_token(identity=username, additional_claims=claims)
    
    refresh_token_id : str = decode_token(refresh_token)["jti"]
    sec = Security()
    sec.save_token(user_id, token_data, refresh_token_id, access_token, channel, previous_refresh_id)
    del sec

    clean_data(user, client, system )

    response = {
        "access_token"  : access_token,
        "refresh_token" : refresh_token,
        "user"          : user,
        "client"        : client,
        "system"        : system,
        "channel"       : channel
    }

    return jsonify(response), 200

@jwt.expired_token_loader
def expired_callback(jwt_header, jwt_payload):
    logger.error(f"Token jwt {jwt_payload['jti']} expirado...")
    return jsonify({"message": "Tu sesión ha expirado"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.error(f"Token invalido: {error}")
    return jsonify({"message": "El token de seguridad no es válido. Acceso denegado."}), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    logger.error(f"Token no encontrado: {error}")
    return jsonify({"message": "No se encontró un token de acceso. Debes iniciar sesión."}), 401

@app.delete(f"{CONTEXT_PATH}/logout")
@jwt_required()
def logout():
    """
    Cerrar Sesión - Revocar Token
    ---
    tags:
      - Autenticación
    security:
      - BearerAuth: []
    parameters:
      - in: header
        name: x-api-key
        required: true
        schema:
          type: string
        description: UUID del sistema SaaS (saas_system.uuid)
      - in: header
        name: client-id
        required: true
        schema:
          type: string
        description: UUID del cliente/tenant (tenant.uuid)
      - in: header
        name: Authorization
        required: true
        schema:
          type: string
        description: Token de acceso en formato "Bearer {token}"
    responses:
      200:
        description: Sesión cerrada exitosamente
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/MessageResponse'
      401:
        description: Token no válido o no proporcionado
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ErrorResponse'
    """
    logger.info(f"INIT: {CONTEXT_PATH}/logout... ")
    sec = Security()
    jwt = get_jwt()
    jti = jwt["jti"]

    # Se resuelve el contexto (sistema por x-api-key y cliente por client-id) para
    # validar que el token pertenezca a ese cliente/sistema antes de revocarlo.
    # No se exige contrato vigente: un usuario siempre puede cerrar su propia sesión.
    system : dict = sec.get_system(request.headers.get('x-api-key'))
    tenant : dict = sec.get_tenant(request.headers.get('client-id'))
    if system == None or tenant == None :
        logger.error("Logout con sistema y/o cliente no resueltos desde los headers")
        del sec
        return jsonify({"message": "No autorizado"}), 401
    if str(jwt.get("tenant")) != str(tenant["uuid"]) or str(jwt.get("system")) != str(system["uuid"]) :
        logger.error(f"Token no corresponde al cliente[{tenant['uuid']}]/sistema[{system['uuid']}]")
        del sec
        return jsonify({"message": "Token no autorizado para este cliente/sistema"}), 401

    sec.delete_token(jti)
    del sec
    return jsonify({"message": "Sesión cerrada con exito"}), 200

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict):
    sec = Security()
    status : bool = sec.is_token_revoked(jwt_payload)
    logger.info(f"Token revoked: {status}")
    del sec
    return status

# ===============================================================================
# Metodo Principal que levanta el servidor
# ===============================================================================
if __name__ == "__main__":
    listenPort = 8079
    logger.info("ROOT_DIR: " + ROOT_DIR)
    logger.info("ROOT_DIR: " + app.root_path)
    if(len(sys.argv) == 1):
        logger.error("Se requiere el puerto como parametro")
        exit(0)
    try:
        logger.info("Server listen at: " + sys.argv[1])
        # La columna user_jwt.channel sostiene las sesiones simultáneas web/móvil: sin
        # ella ningún login queda registrado y todas las peticiones responderían 401.
        _sec = Security()
        if _sec.has_channel_column() == False :
            logger.error("FALTA la columna user_jwt.channel: ejecuta la migración del README "
                         "antes de atender tráfico (ALTER TABLE user_jwt ADD COLUMN channel ...)")
        else :
            logger.info(f"Sesiones por canal habilitadas {Security.CHANNELS} "
                        f"(refresh: {REFRESH_EXPIRES_IN_DAYS} días)")
        del _sec
        if len(ALLOWED_NETWORKS) == 0 :
            logger.warning("ALLOWED_NETWORKS vacío: la API acepta peticiones desde CUALQUIER origen")
        else :
            logger.info(f"Redes autorizadas: {[str(n) for n in ALLOWED_NETWORKS]} "
                        f"(proxies de confianza: {TRUSTED_PROXY_COUNT}, público: {list(PUBLIC_PATHS)})")
        listenPort = int(sys.argv[1])
        # app.run( ssl_context='adhoc', host='0.0.0.0', port=listenPort, debug=True)
        # app.run( ssl_context=('cert_jonnattan.pem', 'key_jonnattan.pem'), host='0.0.0.0', port=listenPort, debug=True)
        app.run( host='0.0.0.0', port=listenPort, debug=True)
    except Exception as e:
        print("ERROR MAIN:", e)

    logging.info("PROGRAM FINISH")
