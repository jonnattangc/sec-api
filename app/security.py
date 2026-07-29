try:
    import logging
    import sys
    import os
    import pymysql.cursors
    from datetime import datetime, timedelta
    from werkzeug.security import generate_password_hash, check_password_hash

except ImportError:
    logging.error(ImportError)
    print((os.linesep * 2).join(['[Security] Error al buscar los modulos:', str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)

class Security() :
    db = None

    def __init__(self) :
        try:
            host : str = os.environ.get('HOST_BD', None)
            port : int = int(os.environ.get('PORT_BD', -1))
            user_bd : str  = os.environ.get('USER_BD', None)
            pass_bd : str  = os.environ.get('PASS_BD', None)
            eschema : str  = os.environ.get('SCHEMA_BD', None)

            self.db = pymysql.connect(host=host, port=port, 
                user=user_bd, password=pass_bd, database=eschema, 
                cursorclass=pymysql.cursors.DictCursor)

            # logging.info(f"Conectado a BD: {host}:{port}/{eschema} con usuario: {user_bd}")
        
        except Exception as e :
            print("ERROR __init__: ", e)
            self.db = None

    def __del__(self):
        if self.db != None:
            self.db.close()

    # Estados considerados "vigentes" para un contrato tenant-sistema.
    # El enum en BD es ('ACTIVE','INACTIVE','DEMO'); se tratan como vigentes
    # 'ACTIVE' y 'DEMO' (contrato de prueba). 'INACTIVE' no autoriza.
    CONTRACT_ACTIVE_STATUS = ('ACTIVE', 'DEMO')

    # Canales desde los que se puede abrir una sesión (columna user_jwt.channel).
    # Un usuario puede tener sesiones simultáneas en ambos: la consola web y la
    # aplicación móvil son sesiones independientes y no se expulsan entre sí.
    CHANNELS = ('WEB', 'MOBILE')
    DEFAULT_CHANNEL = 'WEB'

    # Vida del refresh token: pasado ese plazo sin renovar, la sesión ya no puede
    # revivir y su fila en user_jwt se purga. Debe coincidir con la configuración
    # JWT_REFRESH_TOKEN_EXPIRES del servidor.
    REFRESH_EXPIRES_DAYS : int = int(os.environ.get('REFRESH_EXPIRES_IN_DAYS', 30))

    def get_system( self, api_key_rx : str ) -> dict :
        """Resuelve el sistema (saas_system) a partir del x-api-key (uuid del sistema)."""
        logging.info(f"Busco sistema con x-api-key: {api_key_rx}")
        system : dict = None
        try :
            if api_key_rx == None :
                return system
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from saas_system where uuid = %s and status = %s"""
                cursor.execute(sql, (api_key_rx, 'ENABLED'))
                results = cursor.fetchall()
                for row in results:
                    system = row
                    break
        except Exception as e:
            print("ERROR BD get_system():", e)
        return system

    def get_tenant( self, client_id_rx : str ) -> dict :
        """Resuelve el cliente/tenant a partir del client-id (apikey del tenant)."""
        logging.info(f"Busco cliente con client-id: {client_id_rx}")
        tenant : dict = None
        try :
            if client_id_rx == None :
                return tenant
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from tenant where uuid = %s"""
                cursor.execute(sql, (client_id_rx,))
                results = cursor.fetchall()
                for row in results:
                    tenant = row
                    break
        except Exception as e:
            print("ERROR BD get_tenant():", e)
        return tenant

    def get_active_contract( self, tenant_id, system_id ) -> dict :
        """Verifica que exista un contrato vigente entre el tenant y el sistema.

        Un contrato es vigente si su estado está en CONTRACT_ACTIVE_STATUS y no ha
        vencido (finish_at nulo o en el futuro). Devuelve el contrato o None."""
        logging.info(f"Verifico contrato vigente tenant[{tenant_id}] - sistema[{system_id}]")
        contract : dict = None
        try :
            if tenant_id == None or system_id == None :
                return contract
            if self.db != None :
                cursor = self.db.cursor()
                placeholders = ", ".join(["%s"] * len(self.CONTRACT_ACTIVE_STATUS))
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                sql = f"""select * from tenant_contract
                          where tenant_id = %s and system_id = %s
                            and status in ({placeholders})
                            and (finish_at is null or finish_at > %s)"""
                params = (tenant_id, system_id) + self.CONTRACT_ACTIVE_STATUS + (now,)
                cursor.execute(sql, params)
                results = cursor.fetchall()
                for row in results:
                    contract = row
                    break
        except Exception as e:
            print("ERROR BD get_active_contract():", e)
        return contract

    def verify_credentials( self, username, password, client = dict ) -> dict :
        logging.info(f"Verifico credeciales para usuario: {username} y tenant: {client['id']}")
        user : dict = None
        try :
            if username == None or password == None:
                return user
            if self.db != None :
                cursor = self.db.cursor()
                tenant : str = client['id']
                sql = """select * from oauth where username = %s and status = %s and tenant_id = %s"""
                cursor.execute(sql, (username,'ACTIVE', tenant))
                results = cursor.fetchall()
                if len(results) == 0 :
                    logging.info(f"Usuario no encontrado: {username} de tenant: {tenant}")
                for row in results:
                    user = row
                    logging.info(f"Usuario encontrado con ID: {user['id']}")
                    if user != None :
                        bd_pass : str = str(user['password'])
                        db_user : str = str(user['username'])
                        if db_user != None and bd_pass != None :
                            check = check_password_hash(bd_pass, password )
                            if db_user != username or not check :
                                user = None
                            else :
                                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                self.update_login(username, now)
                                user['last_login'] = now
                        else :
                            user = None
                    break
        except Exception as e:
            print("ERROR BD:", e)
        return user

    def update_login(self, username, now = None) :
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """UPDATE oauth SET last_login = %s WHERE username = %s"""
                cursor.execute(sql, (now, username))
                self.db.commit()
        except Exception as e:
            print("ERROR BD:", e)
            self.db.rollback()

    def user_generate(self, user, password) :
        logging.info("Genero nuevo usuario: " + str(user) )
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """INSERT INTO oauth (create_at, username, password, status, role) VALUES(%s, %s, %s, %s, %s)"""
                now = datetime.now()
                cursor.execute(sql, (now.strftime("%Y-%m-%d %H:%M:%S"), user, generate_password_hash(password), 'ACTIVE', 'USER'))
                self.db.commit()
        except Exception as e:
            print("ERROR BD:", e)
            self.db.rollback()

    def user_exists(self, username: str, tenant: str) -> dict :
        logging.info(f"Verifico existencia de usuario: {username}" )
        user : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from oauth where username = %s and status = %s and tenant_id = %s"""
                cursor.execute(sql, (username,'ACTIVE', tenant))
                results = cursor.fetchall()
                for row in results:
                    user = row
                    break
        except Exception as e:
            print("ERROR BD user_exists():", e)
        return user

    def save_token(self, user_id: str, data_token: dict, refresh_token_id: str, token_jwt: str,
                   channel: str = None, previous_refresh_id: str = None) :
        """Registra la sesión recién emitida en user_jwt.

        Cada sesión es una fila propia: un usuario puede estar conectado a la vez desde
        la consola web y desde la aplicación móvil (e incluso varias veces por canal).
        Antes se borraban todas las sesiones del usuario en cada login, de modo que el
        último ingreso expulsaba al anterior; ahora solo se retira la sesión que se está
        rotando (`previous_refresh_id`, en el refresh) y las ya expiradas."""
        channel = channel if channel in self.CHANNELS else self.DEFAULT_CHANNEL
        try :
            token : dict = None
            id_token : str = data_token['jti']
            date_str : str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s"""
                cursor.execute(sql, (id_token,))
                token = cursor.fetchone()
                if token != None :
                    logging.info(f"Actualizo token: {token['id']} del usuario: {token['user_id']}")
                    sql = """UPDATE user_jwt SET update_at = %s, token = %s, refresh_id = %s, channel = %s WHERE id = %s"""
                    cursor.execute(sql, (date_str, token_jwt, refresh_token_id, channel, id_token,))
                else :
                    logging.info(f"Guardo la sesión {id_token} (canal {channel}) del usuario {user_id}")
                    if previous_refresh_id != None :
                        # Rotación del refresh: la sesión continúa, cambia su par de tokens.
                        cursor.execute("delete from user_jwt where refresh_id = %s", (previous_refresh_id,))
                    sql = """INSERT INTO user_jwt (id, create_at, update_at, user_id, status, token, refresh_id, channel)
                             VALUES(%s, %s, %s, %s, %s, %s, %s, %s)"""
                    cursor.execute(sql, (id_token, date_str, date_str, user_id, 'ACTIVE', token_jwt, refresh_token_id, channel))
                self.db.commit()
                self.purge_expired_tokens(user_id)
        except Exception as e:
            print("ERROR save_token(): ", e)
            self.db.rollback()


    def purge_expired_tokens(self, user_id: str) :
        """Elimina las sesiones del usuario que ya no pueden renovarse (refresh vencido).
        Evita que las sesiones abandonadas -sin logout- se acumulen en la tabla."""
        try :
            if self.db != None :
                limit = (datetime.now() - timedelta(days=self.REFRESH_EXPIRES_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
                cursor = self.db.cursor()
                cursor.execute("delete from user_jwt where user_id = %s and update_at < %s", (user_id, limit))
                self.db.commit()
        except Exception as e:
            print("ERROR purge_expired_tokens(): ", e)
            self.db.rollback()


    def has_channel_column(self) -> bool :
        """Indica si user_jwt ya tiene la columna `channel`. Sin ella no se pueden
        registrar sesiones y todo login queda inservible, así que el servidor lo avisa
        al arrancar (ver la migración documentada en el README)."""
        row : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute("""select count(*) as total from information_schema.columns
                                  where table_schema = database()
                                    and table_name = 'user_jwt' and column_name = 'channel'""")
                row = cursor.fetchone()
        except Exception as e:
            print("ERROR has_channel_column(): ", e)
            return False
        return row != None and int(row.get('total', 0)) > 0


    def session_channel(self, refresh_id: str) -> str :
        """Devuelve el canal de la sesión dueña de ese refresh token, para conservarlo
        al rotar los tokens. Si la fila es anterior a la columna `channel`, asume WEB."""
        row : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute("select channel from user_jwt where refresh_id = %s", (refresh_id,))
                row = cursor.fetchone()
        except Exception as e:
            print("ERROR session_channel(): ", e)
        if row == None or row.get('channel') not in self.CHANNELS :
            return self.DEFAULT_CHANNEL
        return row['channel']


    def delete_tokens(self, user_id: str) :
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """delete from user_jwt where user_id = %s"""
                logging.info(f"Elimino tokens de usuario: {user_id}")
                cursor.execute(sql, (user_id,))
                self.db.commit()
        except Exception as e:
            print("ERROR delete_tokens(): ", e)
            self.db.rollback()

        
    def delete_token(self, id_token: str) :
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """delete from user_jwt where id = %s"""
                cursor.execute(sql, (id_token,))
                logging.info(f"Elimino token id: {id_token}")
                self.db.commit()
        except Exception as e:
            print("ERROR delete_token(): ", e)
            self.db.rollback()

    def is_token_valid(self, token: dict) -> bool :
        logging.info(f"Verifico validez de token jwt: {token['jti']}" )
        valid : bool = False
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s and status = %s"""
                cursor.execute(sql, (token['jti'], 'ACTIVE'))
                results = cursor.fetchall()
                valid = len(results) > 0
        except Exception as e:
            print("ERROR BD is_token_valid():", e)
            valid = False
        return valid

    def is_refresh_token_valid(self, token: dict) -> bool :
        logging.info(f"Verifico validez de refresh token: {token['jti']}" )
        valid : bool = False
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where refresh_id = %s and status = %s"""
                cursor.execute(sql, (token['jti'], 'ACTIVE'))
                results = cursor.fetchall()
                valid = len(results) > 0
        except Exception as e:
            print("ERROR BD is_refresh_token_valid():", e)
            valid = False
        return valid

    def is_token_revoked(self, token: dict) -> bool :
        logging.info(f"Verifico revocación de token: {token['jti']}" )
        valid : bool = False
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s and status <> %s"""
                cursor.execute(sql, (token['jti'], 'ACTIVE'))
                results = cursor.fetchall()
                valid = len(results) > 0
        except Exception as e:
            print("ERROR BD is_token_revoked():", e)
            valid = False
        return valid