#!/usr/bin/python

try:
    import logging
    import sys
    import os
    import time
    from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, decode_token
    from flask import Flask, request, jsonify
    from werkzeug.middleware.proxy_fix import ProxyFix
    from flasgger import Swagger
    from flask_cors import CORS
    from security import Security

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
SECRET_JWT : str = os.environ.get('SECRET_KEY_JWT','super-secret-key-aca-debe-ir')

CONTEXT_PATH : str = os.environ.get('CONTEXT_PATH','/oauth')

app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

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
                "properties": {
                    "id": {
                        "type": "integer",
                        "example": 1
                    },
                    "username": {
                        "type": "string",
                        "example": "usuario"
                    },
                    "role": {
                        "type": "string",
                        "example": "user"
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
                "properties": {
                    "id": {
                        "type": "integer",
                        "example": 1
                    },
                    "company": {
                        "type": "string",
                        "example": "Mi Empresa"
                    },
                    "status": {
                        "type": "string",
                        "example": "ACTIVE"
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
                    "expires_in": {
                        "type": "integer",
                        "example": 300
                    },
                    "user": {
                        "$ref": "#/components/schemas/User"
                    },
                    "client": {
                        "$ref": "#/components/schemas/Client"
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
    'specs_route': '/apidocs/',
    'doc_dir': str(ROOT_DIR) + '/docs',
    'static_url_path': '/flasgger_static',
    'specs': [
        {
            "endpoint": 'api_oauth',
            "route": '/api_oauth.json',
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
jwt = JWTManager(app)

cors = CORS(app, origins=["https://dev.jonnattan.com", "https://api.jonnattan.cl","https://www.jonna.cl","https://www.jonnattan.cl","https://api.jonna.cl","https://docs.jonna.cl","https://docs.jonnattan.cl"])


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
        description: Clave API del cliente
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
    data_json = {"message": "Validación fallida"}
    http_status = 401
    sec = Security()
    client = sec.get_client(request.headers.get('x-api-key'))
    if client != None :
        logger.info(f"Cliente[{client['id']}]: {client['company']}")
        data_json = {"message": "OK"}
        http_status = 200
        jwt = get_jwt()
        current_user = get_jwt_identity()
        user = sec.user_exists(current_user)
        if jwt == None or str(jwt["client"]) != str(client["id"]) :
            logger.warn(f"Cliente JWT: {jwt["client"]}")
            data_json = {"message": "Cliente y/o usuario no autorizado"}
            http_status = 401
        # verificar el rol del usuario por si fue modificado en el front
        if user == None or str(jwt["role"]).lower() != str(user["role"]).lower() :
            logger.warn(f"Rol JWT: {jwt["role"]} y Rol User: {user['role']}")
            data_json = {"message": "Rol o usuario no autorizado"}
            http_status = 401
        # verifico si el token es valido, es decir no se ha caducado por otro lado
        if sec.is_token_valid( jwt ) == False :
            data_json = {"message": "Token no autorizado"}
            http_status = 401
    del sec
    return jsonify(data_json), http_status


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
        description: Clave API del cliente
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
    sec = Security()
    client = sec.get_client( request.headers.get('x-api-key') )
    if client != None :
        logger.info(f"Cliente: {client['company']}")
        username = request.json.get("username", None)
        password = request.json.get("password", None)
        user = sec.verify_credentials(username, password)
        del sec
        return process_response_jwt( user, client )
    del sec
    return jsonify({"message": "No autorizado"}), 401

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
        description: Clave API del cliente
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
    sec = Security()
    client = sec.get_client( request.headers.get('x-api-key') )
    if client != None :
        logger.info(f"Cliente[{client['id']}]: {client['company']}")
        user_name = get_jwt_identity()
        user = sec.user_exists(user_name)
        jwt = get_jwt()
        logger.info(f"JWT REFRESH: {jwt}")
        if jwt == None or str(jwt["client"]) != str(client["id"]) :
            logger.warn(f"Cliente JWT: {jwt['client']}")
            data_json = {"message": "Cliente y/o usuario no autorizado"}
            http_status = 401
        # verificar el rol del usuario por si fue modificado en el front
        if user == None or jwt == None or str(jwt["role"]).lower() != str(user["role"]).lower()  :
            logger.warn(f"Rol JWT: {jwt["role"]} y Rol User: {user['role']}")
            return jsonify({"message": "Rol o usuario no autorizado para el refresh"}), 401
        valid_token = sec.is_refresh_token_valid( jwt )
        if valid_token == False :
            return jsonify({"message": "Invalid Refresh Token"}), 401
        return process_response_jwt( user, client )
    del sec
    return jsonify({"message": "No autorizado"}), 401

def process_response_jwt( user : dict, client : dict = None ) :
    if user == None :
        return jsonify({"message": f"usuario inválido"}), 401
    try :
        del user["password"]
    except :
        pass
    try :
        del client["mail_pass"]
    except :
        pass
    claims : dict = {
        "client" : str(client["id"]),
        "role"   : str(user["role"]).lower()
    }
    username : str = str(user["username"])
    access_token : str = create_access_token(identity=username, additional_claims=claims)
    token_data : dict = decode_token(access_token)
    refresh_token : str = create_refresh_token(identity=username, additional_claims=claims)
    refresh_token_id : str = decode_token(refresh_token)["jti"]
    sec = Security()
    sec.save_token(username, token_data, refresh_token_id, access_token)
    del sec
    response = {
        "access_token"  : access_token,
        "refresh_token" : refresh_token,
        "expires_in"    : EXPIRES_IN_SECONDS,
        "user"          : user,
        "client"        : client
    }
    
    return jsonify(response), 200

@jwt.expired_token_loader
def expired_callback(jwt_header, jwt_payload):
    return jsonify({"message": "Tu sesión ha expirado"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.error(error)
    return jsonify({"message": "El token de seguridad no es válido. Acceso denegado."}), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
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
        description: Clave API del cliente
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
    jti = get_jwt()["jti"]
    sec = Security()
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
        listenPort = int(sys.argv[1])
        # app.run( ssl_context='adhoc', host='0.0.0.0', port=listenPort, debug=True)
        # app.run( ssl_context=('cert_jonnattan.pem', 'key_jonnattan.pem'), host='0.0.0.0', port=listenPort, debug=True)
        app.run( host='0.0.0.0', port=listenPort, debug=True)
    except Exception as e:
        print("ERROR MAIN:", e)

    logging.info("PROGRAM FINISH")
