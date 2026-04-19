# API de Seguridad - Servidor OAuth2/JWT

Servidor ligero basado en Flask para autenticación OAuth2 con JWT que gestiona credenciales de usuarios, validación de clientes API y ciclo de vida de tokens JWT. Diseñado como proveedor centralizado de autenticación para servicios internos y microservicios.

## Características

- **Autenticación de Usuarios**: Verificación de usuario/contraseña con hash bcrypt
- **Gestión de Tokens JWT**: Generación de tokens de acceso y refresco con TTL configurable
- **Validación de API Keys**: Autenticación basada en claves de cliente
- **Revocación de Tokens**: Seguimiento y revocación de tokens mediante lista negra
- **Refresco de Tokens**: Emisión de nuevos tokens de acceso usando refresh tokens
- **Soporte CORS**: Manejo configurable de solicitudes entre orígenes
- **Documentación Swagger**: Documentación interactiva de API vía Flasgger

## Inicio Rápido

### Requisitos Previos

- Python 3.10+
- MySQL 5.7+
- Docker & Docker Compose (opcional)

### Instalación

1. **Clonar el repositorio**
   ```bash
   git clone <repository-url>
   cd sec-api
   ```

2. **Instalar dependencias**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurar variables de entorno**
   
   Crear un archivo `.env` o establecer variables de entorno:
   ```bash
   # Configuración de Base de Datos
   HOST_BD=localhost
   PORT_BD=3306
   USER_BD=root
   PASS_BD=password
   SCHEMA_BD=oauth_db
   
   # Configuración JWT
   SECRET_KEY_JWT=tu-clave-super-secreta-cambia-en-produccion
   EXPIRES_TOKEN_IN_SECONDS=300
   
   # Configuración de API
   CONTEXT_PATH=/oauth
   ```

4. **Configurar la base de datos**
   
   Crear las tablas requeridas:
   ```sql
   -- Tabla de usuarios
   CREATE TABLE oauth (
     id INT AUTO_INCREMENT PRIMARY KEY,
     username VARCHAR(255) UNIQUE NOT NULL,
     password VARCHAR(255) NOT NULL,
     role VARCHAR(50) DEFAULT 'USER',
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     last_login TIMESTAMP NULL,
     updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
   );
   
   -- Tabla de clientes API
   CREATE TABLE clients (
     id INT AUTO_INCREMENT PRIMARY KEY,
     company VARCHAR(255) NOT NULL,
     apikey VARCHAR(255) UNIQUE NOT NULL,
     mail_pass VARCHAR(255),
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );
   
   -- Tabla de seguimiento de tokens JWT
   CREATE TABLE user_jwt (
     id VARCHAR(255) PRIMARY KEY,
     user VARCHAR(255) NOT NULL,
     token LONGTEXT NOT NULL,
     refresh_id VARCHAR(255),
     status VARCHAR(20) DEFAULT 'ACTIVE',
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     FOREIGN KEY (user) REFERENCES oauth(username)
   );
   ```

5. **Ejecutar el servidor**
   ```bash
   python app/server.py 8079
   ```
   
   La API estará disponible en `http://localhost:8079`
   
   Documentación Swagger disponible en `http://localhost:8079/apidocs/`

### Despliegue con Docker

1. **Construir la imagen**
   ```bash
   docker build -t security:prd .
   ```

2. **Ejecutar con docker-compose**
   
   Crear `envs/security.env`:
   ```
   HOST_BD=db
   PORT_BD=3306
   USER_BD=root
   PASS_BD=rootpassword
   SCHEMA_BD=oauth_db
   SECRET_KEY_JWT=tu-clave-segura
   EXPIRES_TOKEN_IN_SECONDS=300
   CONTEXT_PATH=/oauth
   ```
   
   Iniciar los contenedores:
   ```bash
   docker-compose up -d
   ```

## Endpoints de la API

### 1. Iniciar Sesión
**POST** `/oauth/login`

Autentica un usuario y obtiene tokens JWT.

**Encabezados:**
```
x-api-key: tu_clave_api
Content-Type: application/json
```

**Cuerpo de la Solicitud:**
```json
{
  "username": "usuario",
  "password": "contraseña_segura"
}
```

**Respuesta Exitosa (200):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "user": {
    "id": 1,
    "username": "usuario",
    "role": "user",
    "status": "ACTIVE",
    "last_login": "2026-04-19 10:30:00"
  },
  "client": {
    "id": 1,
    "company": "Mi Empresa",
    "status": "ACTIVE"
  }
}
```

**Respuesta de Error (401):**
```json
{
  "message": "No autorizado"
}
```

### 2. Validar Token
**GET** `/oauth/validate`

Verifica que un token sea válido y el usuario tenga acceso adecuado.

**Encabezados:**
```
Authorization: Bearer {access_token}
x-api-key: tu_clave_api
```

**Respuesta Exitosa (200):**
```json
{
  "message": "OK"
}
```

**Respuesta de Error (401):**
```json
{
  "message": "Token no autorizado"
}
```

### 3. Refrescar Token
**GET** `/oauth/refresh`

Genera un nuevo token de acceso usando un refresh token válido.

**Encabezados:**
```
Authorization: Bearer {refresh_token}
x-api-key: tu_clave_api
```

**Respuesta Exitosa (200):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "expires_in": 300,
  "user": {
    "id": 1,
    "username": "usuario",
    "role": "user",
    "status": "ACTIVE"
  },
  "client": {
    "id": 1,
    "company": "Mi Empresa"
  }
}
```

**Respuesta de Error (401):**
```json
{
  "message": "Tu sesión ha expirado"
}
```

### 4. Cerrar Sesión
**DELETE** `/oauth/logout`

Revoca el token de acceso actual e invalida la sesión.

**Encabezados:**
```
Authorization: Bearer {access_token}
x-api-key: tu_clave_api
```

**Respuesta Exitosa (200):**
```json
{
  "message": "Sesión cerrada con éxito"
}
```

**Respuesta de Error (401):**
```json
{
  "message": "No se encontró un token de acceso. Debes iniciar sesión."
}
```

## Flujo de Autenticación

```
┌─────────────┐
│   Cliente   │
└──────┬──────┘
       │
       │ 1. POST /oauth/login (usuario + contraseña + x-api-key)
       ↓
┌────────────────────┐
│  Validar API Key   │
└────────┬───────────┘
         │
         │ 2. Buscar cliente en tabla clients
         ↓
┌────────────────────────┐
│ Verificar Credenciales │
└────────┬───────────────┘
         │
         │ 3. Buscar usuario en tabla oauth, verificar hash
         ↓
┌────────────────────┐
│ Generar JWT Pair   │
└────────┬───────────┘
         │
         │ 4. Crear access_token + refresh_token
         ↓
┌────────────────────────────┐
│ Guardar Tokens en BD       │
└────────┬───────────────────┘
         │
         │ 5. Guardar tokens en tabla user_jwt
         ↓
┌─────────────────────────┐
│ Retornar Tokens e Info  │
│ del Usuario al Cliente  │
└────────┬────────────────┘
         │
         │ 200 OK + tokens
         ↓
┌─────────────┐
│   Cliente   │
└─────────────┘
```

## Ejemplos de Uso

### Con cURL

**Iniciar sesión:**
```bash
curl -X POST http://localhost:8079/oauth/login \
  -H "x-api-key: tu_clave_api_aqui" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "usuario",
    "password": "contraseña_segura"
  }'
```

**Validar token:**
```bash
curl -X GET http://localhost:8079/oauth/validate \
  -H "Authorization: Bearer eyJhbGc..." \
  -H "x-api-key: tu_clave_api_aqui"
```

**Refrescar token:**
```bash
curl -X GET http://localhost:8079/oauth/refresh \
  -H "Authorization: Bearer refresh_token_aqui" \
  -H "x-api-key: tu_clave_api_aqui"
```

**Cerrar sesión:**
```bash
curl -X DELETE http://localhost:8079/oauth/logout \
  -H "Authorization: Bearer access_token_aqui" \
  -H "x-api-key: tu_clave_api_aqui"
```

### Con Python

```python
import requests

BASE_URL = "http://localhost:8079"
API_KEY = "tu_clave_api_aqui"

# 1. Iniciar sesión
login_response = requests.post(
    f"{BASE_URL}/oauth/login",
    headers={"x-api-key": API_KEY},
    json={
        "username": "usuario",
        "password": "contraseña_segura"
    }
)

tokens = login_response.json()
access_token = tokens["access_token"]
refresh_token = tokens["refresh_token"]

# 2. Validar token
validate_response = requests.get(
    f"{BASE_URL}/oauth/validate",
    headers={
        "Authorization": f"Bearer {access_token}",
        "x-api-key": API_KEY
    }
)

print(validate_response.json())

# 3. Refrescar token
refresh_response = requests.get(
    f"{BASE_URL}/oauth/refresh",
    headers={
        "Authorization": f"Bearer {refresh_token}",
        "x-api-key": API_KEY
    }
)

new_access_token = refresh_response.json()["access_token"]

# 4. Cerrar sesión
logout_response = requests.delete(
    f"{BASE_URL}/oauth/logout",
    headers={
        "Authorization": f"Bearer {access_token}",
        "x-api-key": API_KEY
    }
)

print(logout_response.json())
```

## Configuración

### Variables de Entorno

| Variable | Por Defecto | Descripción |
|----------|-------------|-------------|
| `HOST_BD` | - | Host de la base de datos MySQL |
| `PORT_BD` | 3306 | Puerto de la base de datos MySQL |
| `USER_BD` | - | Usuario de la base de datos MySQL |
| `PASS_BD` | - | Contraseña de la base de datos MySQL |
| `SCHEMA_BD` | - | Nombre del esquema de la base de datos |
| `SECRET_KEY_JWT` | `super-secret-key-aca-debe-ir` | Clave para firmar JWT (⚠️ cambiar en producción) |
| `EXPIRES_TOKEN_IN_SECONDS` | 300 | Tiempo de expiración del token de acceso en segundos |
| `CONTEXT_PATH` | `/oauth` | Ruta base para endpoints OAuth |

### Configuración CORS

La API permite solicitudes desde los siguientes orígenes:
- `https://dev.jonnattan.com`
- `https://api.jonnattan.cl`
- `https://www.jonna.cl`
- `https://www.jonnattan.cl`
- `https://api.jonna.cl`
- `https://docs.jonna.cl`
- `https://docs.jonnattan.cl`

Para modificar, edita la línea `cors = CORS(...)` en `app/server.py`.

## Consideraciones de Seguridad

### Seguridad de Contraseñas
- Las contraseñas se cifran con **bcrypt** vía `generate_password_hash()` de werkzeug
- Las contraseñas en texto plano nunca se almacenan en la base de datos
- Implementa requisitos de fortaleza de contraseña en tu aplicación cliente

### Seguridad JWT
- Los tokens se firman con una clave secreta (`SECRET_KEY_JWT`)
- **⚠️ Cambia la clave secreta por defecto en producción**
- Los tokens de acceso tienen TTL configurable (por defecto: 300 segundos / 5 minutos)
- Los refresh tokens tienen mayor validez y se almacenan en BD para seguimiento de revocación
- Los tokens se invalidan cuando los usuarios cierran sesión

### Gestión de API Keys
- Las claves API se almacenan en la tabla `clients`
- Cada cliente tiene una clave API única
- Las claves API son requeridas para los endpoints `/login` y `/validate`
- Implementa políticas de rotación de claves

### Mejores Prácticas

1. **Usa HTTPS en producción** - Los tokens son sensibles y deben transmitirse de forma segura
2. **TTL corto para tokens de acceso** - Usa tiempos de expiración cortos y refresh tokens para sesiones más largas
3. **Almacenamiento seguro de secretos** - Usa variables de entorno o sistemas de gestión de secretos para `SECRET_KEY_JWT`
4. **Seguridad de la base de datos** - Limita el acceso, usa credenciales fuertes, habilita SSL/TLS para conexiones BD
5. **Rate limiting** - Implementa límite de tasas en el endpoint `/login` para prevenir ataques de fuerza bruta
6. **Logging** - Monitorea logs de autenticación para actividad sospechosa

## Desarrollo

### Estructura del Proyecto

```
sec-api/
├── app/
│   ├── server.py          # Aplicación Flask principal y endpoints OAuth
│   └── security.py        # Lógica de autenticación y gestión de tokens
├── requirements.txt       # Dependencias de Python
├── Dockerfile            # Definición de imagen del contenedor
├── docker-compose.yml    # Configuración de Docker Compose
├── CLAUDE.md             # Guía para Claude Code
└── README.md             # Este archivo
```

### Pruebas Locales

Crea un cliente de prueba en la tabla `clients`:

```sql
INSERT INTO clients (company, apikey) VALUES ('Empresa de Prueba', 'clave_api_prueba_123');
```

Crea un usuario de prueba en la tabla `oauth`:

```sql
INSERT INTO oauth (username, password, role) 
VALUES ('usuario_prueba', '...hash_bcrypt...', 'user');
```

Usa los ejemplos de cURL o Python proporcionados para probar los endpoints.

### Logging

La aplicación registra todos los eventos de autenticación en stdout con formato:
```
2026-04-19 10:30:00,123 INFO : Cliente: Mi Empresa
```

Ver logs en Docker:
```bash
docker-compose logs -f test-api
```

## Solución de Problemas

### Problemas de Conexión a Base de Datos
- Verifica que MySQL esté ejecutándose y sea accesible
- Verifica variables de entorno (`HOST_BD`, `PORT_BD`, `USER_BD`, `PASS_BD`, `SCHEMA_BD`)
- Asegúrate de que el esquema de la base de datos exista y las tablas estén creadas

### Fallos de Autenticación
- Verifica que la API key exista en la tabla `clients` y sea correcta
- Asegúrate de que el usuario exista en la tabla `oauth` con `status='ACTIVE'`
- Confirma que el hash de la contraseña sea válido (usa bcrypt para crear usuarios de prueba)

### Validación de Token Falla
- Asegúrate de que el token existe en la tabla `user_jwt` con `status='ACTIVE'`
- Verifica que el token no haya expirado (`create_at + EXPIRES_TOKEN_IN_SECONDS`)
- Comprueba que el token no fue revocado por logout

### Puerto Already in Use (Ya en Uso)
Cambia el puerto al ejecutar localmente:
```bash
python app/server.py 8080
```

## Soporte

Para problemas, preguntas o contribuciones, abre un issue en el repositorio.

## Licencia

[Añade tu información de licencia aquí]
