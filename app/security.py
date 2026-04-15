try:
    import logging
    import sys
    import os
    import pymysql.cursors
    from datetime import datetime
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
        
        except Exception as e :
            print("ERROR __init__:", e)
            self.db = None

    def __del__(self):
        if self.db != None:
            self.db.close()

    def get_client( self, api_key_rx : str ) -> dict :
        #logging.info(f"Busco cliente: {api_key_rx}")
        client : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from clients where apikey = %s"""
                cursor.execute(sql, (api_key_rx,))
                results = cursor.fetchall()
                for row in results:
                    client = row
                    break
        except Exception as e:
            print("ERROR BD:", e)
        return client

    def verify_credentials( self, username, password ) -> dict :
        logging.info(f"Verifico credeciales para usuario: {username}")
        user : dict = None
        try :
            if username == None or password == None:
                return user
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from oauth where username = %s and status = %s"""
                cursor.execute(sql, (username,'ACTIVE'))
                results = cursor.fetchall()
                for row in results:
                    user = row
                    # logging.info(f"Usuario encontrado: {user}")
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

    def user_exists(self, username: str) -> dict :
        logging.info(f"Verifico existencia de usuario: {username}" )
        user : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from oauth where username = %s and status = %s"""
                cursor.execute(sql, (username,'ACTIVE'))
                results = cursor.fetchall()
                for row in results:
                    user = row
                    break
        except Exception as e:
            print("ERROR BD:", e)
        return user

    def save_token(self, username: str, data_token: dict, refresh_token_id: str, token_jwt: str) :
        try :
            user : dict = None
            id_token : str = data_token['jti']
            date_str : str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s"""
                cursor.execute(sql, (id_token,))
                user = cursor.fetchone()
                if user != None :
                    logging.info(f"Actualizo token: {user['id']}")
                    sql = """UPDATE user_jwt SET create_at = %s, token = %s, refresh_id = %s WHERE id = %s"""
                    cursor.execute(sql, (date_str, token_jwt, refresh_token_id,id_token,))
                else :
                    logging.info(f"Guardo último token creado: {id_token} refresh: {refresh_token_id}")
                    self.delete_tokens(username)
                    sql = """INSERT INTO user_jwt (id, create_at, user, status, token, refresh_id) VALUES(%s, %s, %s, %s, %s, %s)"""
                    cursor.execute(sql, (id_token, date_str, username, 'ACTIVE', token_jwt, refresh_token_id))
                self.db.commit()
        except Exception as e:
            print("ERROR save_token(): ", e)
            self.db.rollback()


    def delete_tokens(self, username: str) :
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """delete from user_jwt where user = %s"""
                cursor.execute(sql, (username,))
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
                self.db.commit()
        except Exception as e:
            print("ERROR delete_token(): ", e)
            self.db.rollback()

    def is_token_valid(self, token: dict) -> bool :
        logging.info(f"Verifico validez de token: {token['jti']}" )
        valid : bool = False
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s and status = %s order by create_at desc"""
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
                sql = """select * from user_jwt where refresh_id = %s and status = %s order by create_at desc"""
                cursor.execute(sql, (token['jti'], 'ACTIVE'))
                results = cursor.fetchall()
                valid = len(results) > 0
        except Exception as e:
            print("ERROR BD is_token_valid():", e)
            valid = False
        return valid

    def is_token_revoked(self, token: dict) -> bool :
        logging.info(f"Verifico revocación de token: {token['jti']}" )
        valid : bool = False
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """select * from user_jwt where id = %s and status <> %s order by create_at desc"""
                cursor.execute(sql, (token['jti'], 'ACTIVE'))
                results = cursor.fetchall()
                valid = len(results) > 0
        except Exception as e:
            print("ERROR BD is_token_valid():", e)
            valid = False
        return valid