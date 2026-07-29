# API de Seguridad - Servidor OAuth2/JWT

Servidor ligero basado en Flask para autenticación OAuth2 con JWT que gestiona credenciales de usuarios, validación multi-tenant por contrato y ciclo de vida de tokens JWT. Diseñado como proveedor centralizado de autenticación para servicios internos y microservicios.

## Modelo multi-tenant (sistema + cliente + contrato)

La autenticación es multi-tenant y se apoya en dos identificadores enviados por cabecera:

- **`x-api-key` → Sistema**: identifica el **sistema SaaS** que consume la API. Su valor es el `uuid` de la tabla `saas_system` (debe estar `ENABLED`).
- **`client-id` → Cliente/Tenant**: identifica al **cliente**. Su valor es el `uuid` de la tabla `tenant`.

**Regla principal:** un usuario solo puede autenticarse si existe un **contrato vigente** entre su cliente (tenant) y el sistema, registrado en la tabla `tenant_contract` con estado `ACTIVE` o `DEMO` y sin vencer (`finish_at` nulo o futuro). Esta validación de contrato se aplica en `/login`, `/validate` y `/refresh`.

## Características

- **Autenticación de Usuarios**: Verificación de usuario/contraseña con hash bcrypt, aislada por tenant
- **Autorización por contrato**: Login/validate/refresh exigen un contrato sistema↔cliente vigente
- **Gestión de Tokens JWT**: Generación de tokens de acceso y refresco con TTL configurable; los claims incluyen `tenant` y `system`
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
   -- Sistemas SaaS que consumen la API (identificados por uuid vía x-api-key)
   CREATE TABLE saas_system (
     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     name VARCHAR(255) NOT NULL,
     visible TINYINT(1) NOT NULL,
     uuid VARCHAR(255) NOT NULL,
     status ENUM('ENABLED','DISABLED')
   );

   -- Clientes/tenants (identificados por uuid vía client-id)
   CREATE TABLE tenant (
     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     name_company VARCHAR(255) NOT NULL,
     uuid VARCHAR(255) NOT NULL UNIQUE,
     razon_social VARCHAR(255),
     contacto VARCHAR(255),
     mail_contacto VARCHAR(255)
   );

   -- Contrato entre un tenant y un sistema (habilita el login)
   CREATE TABLE tenant_contract (
     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     create_at DATETIME,
     update_at DATETIME,
     tenant_id BIGINT UNSIGNED,
     system_id BIGINT UNSIGNED,
     signature_id BIGINT UNSIGNED,
     signature_date DATETIME,
     finish_at DATETIME,
     status ENUM('ACTIVE','INACTIVE','DEMO'),
     FOREIGN KEY (tenant_id) REFERENCES tenant(id),
     FOREIGN KEY (system_id) REFERENCES saas_system(id)
   );

   -- Usuarios, aislados por tenant
   CREATE TABLE oauth (
     id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
     create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
     update_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
     username VARCHAR(255) NOT NULL,
     password VARCHAR(255) NOT NULL,
     last_login TIMESTAMP NULL,
     status ENUM('ACTIVE','INACTIVE','PENDING','BLOCKED'),
     role ENUM('SUPERADMIN','ADMIN','USER','QUERY') NOT NULL DEFAULT 'USER',
     realname VARCHAR(255),
     claims VARCHAR(255),
     tenant_id BIGINT UNSIGNED NOT NULL,
     FOREIGN KEY (tenant_id) REFERENCES tenant(id)
   );

   -- Seguimiento de tokens JWT: una fila por SESIÓN abierta
   CREATE TABLE user_jwt (
     id VARCHAR(255) PRIMARY KEY,
     create_at TIMESTAMP NOT NULL,
     update_at TIMESTAMP NOT NULL,
     user_id BIGINT UNSIGNED,
     status ENUM('ACTIVE','BLOCKED','EXPIRED') DEFAULT 'ACTIVE',
     token TEXT NOT NULL,
     refresh_id VARCHAR(255) NOT NULL,
     channel ENUM('WEB','MOBILE') NOT NULL DEFAULT 'WEB',
     FOREIGN KEY (user_id) REFERENCES oauth(id),
     INDEX idx_user_jwt_user (user_id),
     INDEX idx_user_jwt_refresh (refresh_id)
   );
   ```

   **Migración de una instalación existente** (sesiones simultáneas web + móvil):

   ```sql
   ALTER TABLE user_jwt
     ADD COLUMN channel ENUM('WEB','MOBILE') NOT NULL DEFAULT 'WEB' AFTER refresh_id,
     ADD INDEX idx_user_jwt_user (user_id),
     ADD INDEX idx_user_jwt_refresh (refresh_id);
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

> **Todos los endpoints requieren ambas cabeceras** `x-api-key` (uuid del sistema) y `client-id` (uuid del tenant). Si el sistema no está `ENABLED`, el cliente no existe o no hay contrato vigente entre ambos, la respuesta es `401 No autorizado`.

### 1. Iniciar Sesión
**POST** `/oauth/login`

Autentica un usuario y obtiene tokens JWT. Requiere contrato vigente entre el cliente y el sistema.

**Encabezados:**
```
x-api-key: {uuid_del_sistema}
client-id: {uuid_del_tenant}
x-channel:  WEB | MOBILE        (opcional, WEB por omisión)
Content-Type: application/json
```

`x-channel` declara desde dónde se abre la sesión y lo envía el backend dueño de ella,
nunca el navegador. Cada login crea su **propia** sesión en `user_jwt`: un mismo usuario
puede estar conectado a la vez en la consola web y en la aplicación móvil, y el logout de
una no afecta a la otra. El refresh **rota** los tokens de esa sesión conservando su canal.

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
  "user": {
    "username": "usuario",
    "realname": "Nombre Real",
    "role": "USER",
    "claims": "RW",
    "status": "ACTIVE",
    "last_login": "2026-04-19 10:30:00"
  },
  "client": {
    "name_company": "Mi Empresa",
    "razon_social": "Mi Empresa S.A.",
    "contacto": "Juan Pérez",
    "mail_contacto": "contacto@miempresa.com"
  },
  "system": {
    "name": "notification",
    "visible": 1
  }
}
```

> Nota: por seguridad, los campos internos (`id`, `uuid`, `tenant_id`, `password`, `create_at`, `update_at`) se eliminan de la respuesta.

**Respuesta de Error (401):**
```json
{
  "message": "No autorizado"
}
```

### 2. Validar Token
**GET** `/oauth/validate`

Verifica que un token sea válido, que el contrato siga vigente y que el usuario tenga acceso adecuado.

**Encabezados:**
```
Authorization: Bearer {access_token}
x-api-key: {uuid_del_sistema}
client-id: {uuid_del_tenant}
```

**Respuesta Exitosa (200):**
```json
{
  "message": "OK",
  "user": { "username": "usuario", "role": "USER", "claims": "RW", "status": "ACTIVE" },
  "client": { "name_company": "Mi Empresa" },
  "system": { "name": "notification" }
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

Genera un nuevo token de acceso usando un refresh token válido. Revalida el contrato vigente.

**Encabezados:**
```
Authorization: Bearer {refresh_token}
x-api-key: {uuid_del_sistema}
client-id: {uuid_del_tenant}
```

**Respuesta Exitosa (200):**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "user": {
    "username": "usuario",
    "role": "USER",
    "claims": "RW",
    "status": "ACTIVE"
  },
  "client": {
    "name_company": "Mi Empresa"
  },
  "system": {
    "name": "notification"
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

Revoca el token de acceso actual e invalida la sesión. Valida que el token pertenezca al cliente/sistema indicados (no exige contrato vigente).

**Encabezados:**
```
Authorization: Bearer {access_token}
x-api-key: {uuid_del_sistema}
client-id: {uuid_del_tenant}
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

## Administración y Onboarding (self-service)

Además del ciclo OAuth existen servicios para **autogestión** (un prospecto contrata un SaaS del
catálogo) y **administración** (CRUD de usuarios, tenants, sistemas y contratos).

### Modelo de roles

- **Super-admin**: usuario con `role='ADMIN'` que pertenece al *tenant plataforma* (definido por la
  env `PLATFORM_TENANT_ID`). Gestiona sistemas, tenants y contratos, y usuarios de cualquier tenant.
- **Tenant-admin**: usuario con `role='ADMIN'` de un tenant normal. Gestiona **solo los usuarios de
  su propio tenant**. El primer usuario creado en el onboarding es un tenant-admin.

Los endpoints de administración se protegen con el **JWT** emitido por `/oauth/login` (rol ADMIN).

### Endpoints públicos (onboarding)

**GET** `/oauth/catalog` — lista los sistemas SaaS contratables (visibles y habilitados).
```json
{ "systems": [ { "name": "sms_resent", "uuid": "87ebf297-..." } ] }
```

**POST** `/oauth/register` — alta self-service. Crea el tenant, un contrato `DEMO` y el primer
usuario ADMIN, todo activo de inmediato.
```bash
curl -X POST http://localhost:8079/oauth/register -H "Content-Type: application/json" -d '{
  "system_uuid": "87ebf297-...",
  "company": { "name_company": "Mi Empresa", "mail_contacto": "contacto@miempresa.com" },
  "user": { "username": "admin", "password": "secreta", "full_name": "Juan Pérez" }
}'
```
Respuesta `201` (usar `client_id` y `x_api_key` para el `/oauth/login`):
```json
{ "message": "Registro exitoso", "client_id": "<tenant.uuid>", "x_api_key": "<system.uuid>", "user": { "...": "..." } }
```

### Endpoints de administración (requieren `Authorization: Bearer <JWT ADMIN>`)

| Recurso | Endpoints | Rol requerido |
|---|---|---|
| Sistemas SaaS | `POST/GET /oauth/admin/systems`, `GET/PUT/DELETE /oauth/admin/systems/{id}` | Super-admin |
| Tenants | `POST/GET /oauth/admin/tenants`, `GET/PUT/DELETE /oauth/admin/tenants/{id}` | Super-admin |
| Contratos | `POST/GET /oauth/admin/contracts`, `GET/PUT/DELETE /oauth/admin/contracts/{id}` | Super-admin |
| Usuarios | `POST/GET /oauth/admin/users`, `GET/PUT/DELETE /oauth/admin/users/{id}` | ADMIN (aislado por tenant) |

Notas:
- `DELETE` de sistemas → baja lógica (`status='DISABLED'`); de usuarios → `status='INACTIVE'` + revoca
  tokens; de contratos → `status='INACTIVE'`. `DELETE` de tenant elimina en cascada controlada
  (desactiva sus contratos y usuarios, revoca tokens).
- Para usuarios, el **super-admin** debe indicar `tenant_id` (en body al crear, en `?tenant_id=` al
  listar); el **tenant-admin** queda forzado a su propio tenant (intentar otro devuelve `403`).
  El `tenant_id` se acepta como id numérico **o** como uuid del tenant (el claim `tenant` del JWT
  es el uuid, y así ambas formas resuelven la misma empresa).
- `GET /oauth/admin/users` agrega a cada usuario sus **sesiones abiertas**, una por canal:

  ```json
  { "id": 7, "username": "ana", "role": "ADMIN", "status": "ACTIVE",
    "sessions": [ { "channel": "WEB",    "last_seen": "2026-07-28 09:12:03", "online": true  },
                  { "channel": "MOBILE", "last_seen": "2026-07-27 22:10:44", "online": false } ] }
  ```

  `online` es verdadero cuando la sesión renovó sus tokens dentro de los últimos
  `SESSION_ONLINE_MINUTES`; una sesión vigente pero inactiva se informa con `online: false`.

Ejemplo (tenant-admin crea un usuario en su tenant):
```bash
curl -X POST http://localhost:8079/oauth/admin/users \
  -H "Authorization: Bearer <JWT_ADMIN>" -H "Content-Type: application/json" \
  -d '{ "username": "operador", "password": "secreta", "role": "USER", "claims": "R" }'
```

### Semilla del super-admin / plataforma

El super-admin obtiene su JWT vía el `/oauth/login` normal, por lo que el tenant plataforma necesita
un sistema "consola" y un contrato activo:
```sql
INSERT INTO saas_system (name, visible, uuid, status)
  VALUES ('console', 0, UUID(), 'ENABLED');
INSERT INTO tenant (name_company, uuid) VALUES ('Plataforma', UUID());
INSERT INTO tenant_contract (create_at, tenant_id, system_id, status)
  VALUES (NOW(), <platform_tenant_id>, <console_system_id>, 'ACTIVE');
INSERT INTO oauth (username, password, status, role, tenant_id)
  VALUES ('superadmin', '<hash_bcrypt>', 'ACTIVE', 'ADMIN', <platform_tenant_id>);
```
Luego define `PLATFORM_TENANT_ID=<platform_tenant_id>` y haz login con
`x-api-key=<uuid-consola>` y `client-id=<uuid-plataforma>`.

## Flujo de Autenticación

```
┌─────────────┐
│   Cliente   │
└──────┬──────┘
       │
       │ 1. POST /oauth/login (usuario + contraseña + x-api-key + client-id)
       ↓
┌──────────────────────────────┐
│ Resolver Sistema (x-api-key)  │  saas_system.uuid, status=ENABLED
└────────┬─────────────────────┘
         │
         │ 2. Resolver Cliente/Tenant (client-id) → tenant.uuid
         ↓
┌──────────────────────────────┐
│ Verificar Contrato Vigente    │  tenant_contract (ACTIVE/DEMO, no vencido)
└────────┬─────────────────────┘
         │
         │ 3. Verificar credenciales del usuario en oauth (aislado por tenant_id)
         ↓
┌────────────────────┐
│ Generar JWT Pair   │  claims: tenant, system, role, claims
└────────┬───────────┘
         │
         │ 4. Crear access_token + refresh_token
         ↓
┌────────────────────────────┐
│ Guardar Tokens en BD       │  tabla user_jwt (por user_id)
└────────┬───────────────────┘
         │
         │ 5. Retornar tokens + user + client + system (sin campos internos)
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
  -H "x-api-key: uuid_del_sistema" \
  -H "client-id: uuid_del_tenant" \
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
  -H "x-api-key: uuid_del_sistema" \
  -H "client-id: uuid_del_tenant"
```

**Refrescar token:**
```bash
curl -X GET http://localhost:8079/oauth/refresh \
  -H "Authorization: Bearer refresh_token_aqui" \
  -H "x-api-key: uuid_del_sistema" \
  -H "client-id: uuid_del_tenant"
```

**Cerrar sesión:**
```bash
curl -X DELETE http://localhost:8079/oauth/logout \
  -H "Authorization: Bearer access_token_aqui" \
  -H "x-api-key: uuid_del_sistema" \
  -H "client-id: uuid_del_tenant"
```

### Con Python

```python
import requests

BASE_URL = "http://localhost:8079"
SYSTEM_UUID = "uuid_del_sistema"   # x-api-key -> saas_system.uuid
TENANT_UUID = "uuid_del_tenant"    # client-id -> tenant.uuid

BASE_HEADERS = {"x-api-key": SYSTEM_UUID, "client-id": TENANT_UUID}

# 1. Iniciar sesión
login_response = requests.post(
    f"{BASE_URL}/oauth/login",
    headers=BASE_HEADERS,
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
    headers={**BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
)

print(validate_response.json())

# 3. Refrescar token
refresh_response = requests.get(
    f"{BASE_URL}/oauth/refresh",
    headers={**BASE_HEADERS, "Authorization": f"Bearer {refresh_token}"}
)

new_access_token = refresh_response.json()["access_token"]

# 4. Cerrar sesión
logout_response = requests.delete(
    f"{BASE_URL}/oauth/logout",
    headers={**BASE_HEADERS, "Authorization": f"Bearer {access_token}"}
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
| `REFRESH_EXPIRES_IN_DAYS` | 30 | Vigencia del refresh token; las sesiones que lo superan se purgan de `user_jwt` |
| `SESSION_ONLINE_MINUTES` | 15 | Minutos sin renovar tras los cuales una sesión deja de reportarse "en línea" |
| `CONTEXT_PATH` | `/oauth` | Ruta base de **todos** los endpoints; administración cuelga de ella (`/oauth/admin`) |
| `PLATFORM_TENANT_ID` | - | Id del tenant plataforma; sus usuarios ADMIN son super-admins |
| `DEMO_TRIAL_DAYS` | 30 | Días de vigencia del contrato DEMO creado en el onboarding |

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

### Gestión de Identificadores (Sistema y Cliente)
- El **sistema** se identifica con `x-api-key` = `saas_system.uuid` (debe estar `ENABLED`)
- El **cliente/tenant** se identifica con `client-id` = `tenant.uuid` (único por cliente)
- Ambas cabeceras son requeridas en todos los endpoints (`/login`, `/validate`, `/refresh`, `/logout`)
- El acceso efectivo lo habilita un **contrato vigente** en `tenant_contract`
- Implementa políticas de rotación de los uuid de sistema/cliente

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
│   ├── server.py          # Aplicación Flask principal, endpoints OAuth y registro de blueprints
│   ├── security.py        # Lógica de autenticación y gestión de tokens
│   ├── admin.py           # Clase Admin: CRUD de sistemas/tenants/contratos/usuarios + onboarding
│   └── routes.py          # Blueprints de administración (/oauth/admin) y onboarding público (/oauth)
├── requirements.txt       # Dependencias de Python
├── Dockerfile            # Definición de imagen del contenedor
├── docker-compose.yml    # Configuración de Docker Compose
├── CLAUDE.md             # Guía para Claude Code
└── README.md             # Este archivo
```

### Pruebas Locales

1. Crea un sistema de prueba en `saas_system`:
   ```sql
   INSERT INTO saas_system (name, visible, uuid, status)
   VALUES ('sistema_prueba', 1, 'uuid-sistema-prueba', 'ENABLED');
   ```

2. Crea un cliente/tenant de prueba en `tenant`:
   ```sql
   INSERT INTO tenant (name_company, uuid) VALUES ('Empresa de Prueba', 'uuid-tenant-prueba');
   ```

3. Registra un contrato vigente entre ambos en `tenant_contract`:
   ```sql
   INSERT INTO tenant_contract (create_at, tenant_id, system_id, status)
   VALUES (NOW(), <tenant_id>, <system_id>, 'ACTIVE');  -- o 'DEMO'
   ```

4. Crea un usuario de prueba asociado al tenant en `oauth`:
   ```sql
   INSERT INTO oauth (username, password, status, role, tenant_id)
   VALUES ('usuario_prueba', '...hash_bcrypt...', 'ACTIVE', 'USER', <tenant_id>);
   ```

Usa los uuid del sistema y del tenant como `x-api-key` y `client-id` en los ejemplos de cURL o Python.

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
- Verifica que el `x-api-key` corresponda a un `saas_system.uuid` con `status='ENABLED'`
- Verifica que el `client-id` corresponda a un `tenant.uuid` existente
- Asegúrate de que exista un contrato vigente en `tenant_contract` (estado `ACTIVE`/`DEMO`, `finish_at` nulo o futuro) entre ese tenant y ese sistema
- Asegúrate de que el usuario exista en la tabla `oauth` con `status='ACTIVE'` y el `tenant_id` correcto
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
