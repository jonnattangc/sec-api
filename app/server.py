#!/usr/bin/python

try:
    import logging
    import sys
    import os
    import time
    import requests
    import json
    from datetime import datetime, timedelta
    import ssl
    from flask_cors import CORS
    
    from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, decode_token

    from flask_login import LoginManager, UserMixin, current_user, login_required, login_user
    from flask import Flask, render_template, abort, make_response, request, redirect, jsonify, send_from_directory
    from werkzeug.middleware.proxy_fix import ProxyFix
    from flask_swagger_ui import get_swaggerui_blueprint
    from flasgger import Swagger
    from security import Security
    from checker import Checker
    from coordinator import Coordinator

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
        "title": "API Documentación",
        "description": "Documentación de mi API con modelos compartidos",
        "version": "1.0.0"
    },
    "components": {
        "schemas": {
            "MiModelo": {  # <--- AQUÍ DEFINES EL MODELO QUE TE DABA ERROR
                "type": "object",
                "properties": {
                    "id": {
                        "type": "integer",
                        "example": 1
                    },
                    "nombre": {
                        "type": "string",
                        "example": "Juan Perez"
                    }
                }
            }
        }
    }
}



app.config['SWAGGER'] = {
    'title': 'API Documentación',
    'uiversion': 3,
    'openapi': '3.0.1', # Forzar versión moderna de OpenAPI
    'specs_route': '/apidocs/',
    'doc_dir': str(ROOT_DIR) + '/docs',
    'static_url_path': '/flasgger_static',
    'specs': [
        {
            "endpoint": 'apijonna',
            "route": '/apijonna.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "headers": [],
    "schemes": ["https"], 
    "static_lib_url": "https://unpkg.com/swagger-ui-dist@3/"
}

swagger = Swagger(app, template=template)

# JWT Manager Config
app.config["JWT_SECRET_KEY"] = SECRET_JWT
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = EXPIRES_IN_SECONDS
jwt = JWTManager(app)

cors = CORS(app, origins=["https://dev.jonnattan.com", "https://api.jonnattan.cl","https://www.jonna.cl","https://www.jonnattan.cl","https://api.jonna.cl","https://docs.jonna.cl","https://docs.jonnattan.cl"])

@app.post(f"{CONTEXT_PATH}/login")
def login():
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
    sec = Security()
    client = sec.get_client( request.headers.get('x-api-key') )
    if client != None :
        logger.info(f"Cliente: {client['company']}")
        user_name = get_jwt_identity()
        user = sec.user_exists(user_name)
        valid_token = sec.is_refresh_token_valid( get_jwt() )
        if valid_token == False :
            return jsonify({"message": "Token Invalido"}), 401
        return process_response_jwt( user )
    del sec
    return jsonify({"message": "No autorizado"}), 401

def process_response_jwt( user : dict, client : dict = None ) :
    if user == None :
        return jsonify({"message": f"usuario inválido"}), 401
    
    if "password" in user :
        del user["password"]

    if "apikey" in client :
        del client["apikey"]

    if "mail_pass" in client :
        del client["mail_pass"]


    claims : dict = {
        "client"       : str(client["id"]),
        "role"          : str(user["role"]).lower()
    }

    username : str = str(user["username"])
    access_token : str = create_access_token(identity=username, additional_claims=claims)
    token_data : dict = decode_token(access_token)
    refresh_token : str = create_refresh_token(identity=username)
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

@app.get(f"{CONTEXT_PATH}/validate")
@jwt_required()
def validate():
    data_json = {"message": "Validación fallida"}
    http_status = 401
    sec = Security()
    client = sec.get_client(request.headers.get('x-api-key'))
    if client != None :
        logger.info(f"Cliente: {client['company']}")
        data_json = {"message": "OK"}
        http_status = 200
        jwt = get_jwt()
        if jwt == None  or jwt["role"] != "query" :
            data_json = {"message": "Rol no autorizado"}
            http_status = 401
        if sec.is_token_valid( jwt ) == False :
            data_json = {"message": "Token no autorizado"}
            http_status = 401
        current_user = get_jwt_identity()
        if current_user == None :
            data_json = {"message": "Usuario no encontrado"}
            http_status = 401
        user = sec.user_exists(current_user)
        if user == None :
            data_json = {"message": "Usuario no encontrado"}
            http_status = 401
    del sec
    return jsonify(data_json), http_status

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
