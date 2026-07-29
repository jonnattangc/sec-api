try:
    import logging
    import sys
    import os
    import uuid
    from datetime import datetime, timedelta
    from werkzeug.security import generate_password_hash
    from security import Security

except ImportError:
    logging.error(ImportError)
    print((os.linesep * 2).join(['[Admin] Error al buscar los modulos:', str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)


# Duración por defecto del trial DEMO al contratar un SaaS (self-service).
DEMO_TRIAL_DAYS : int = int(os.environ.get('DEMO_TRIAL_DAYS', 30))

# Minutos sin renovar el token tras los cuales una sesión deja de considerarse "en
# línea". El access token dura 5 minutos, así que una sesión viva actualiza su fila de
# user_jwt de forma continua; una consola cerrada deja de hacerlo.
SESSION_ONLINE_MINUTES : int = int(os.environ.get('SESSION_ONLINE_MINUTES', 15))

# Valores válidos por columna (para validar entrada antes de escribir en BD).
USER_ROLES = ('SUPERADMIN', 'ADMIN', 'USER', 'QUERY')
USER_STATUS = ('ACTIVE', 'INACTIVE', 'PENDING', 'BLOCKED')
SYSTEM_STATUS = ('ENABLED', 'DISABLED')
CONTRACT_STATUS = ('ACTIVE', 'INACTIVE', 'DEMO')


class Admin(Security) :
    """Operaciones de administración (CRUD) sobre sistemas SaaS, tenants, contratos y
    usuarios, además del alta self-service (onboarding). Hereda de Security para reusar
    la conexión a BD y helpers como get_system/get_tenant/delete_tokens."""

    # ---------------------------------------------------------------- helpers
    def _now(self) -> str :
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _fetch_one(self, sql: str, params: tuple) -> dict :
        row : dict = None
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute(sql, params)
                row = cursor.fetchone()
        except Exception as e :
            print("ERROR BD _fetch_one():", e)
        return row

    def _fetch_all(self, sql: str, params: tuple = ()) -> list :
        rows : list = []
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute(sql, params)
                rows = list(cursor.fetchall())
        except Exception as e :
            print("ERROR BD _fetch_all():", e)
        return rows

    def clean_user(self, user: dict) -> dict :
        """Quita el hash de password de un usuario antes de devolverlo."""
        if user != None and "password" in user :
            del user["password"]
        return user

    # =============================================================== SISTEMAS
    def create_system(self, name: str, visible: int = 1, status: str = 'ENABLED',
                      description: str = None, url: str = None, order: int = None) -> dict :
        try :
            if self.db != None :
                new_uuid = str(uuid.uuid4())
                now = self._now()
                cursor = self.db.cursor()
                sql = """INSERT INTO saas_system (name, visible, uuid, status, description, url, `order`, created_at, updated_at)
                         VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                cursor.execute(sql, (name, int(bool(visible)), new_uuid, status,
                                     description, url, order, now, now))
                self.db.commit()
                return self.get_system_by_id(cursor.lastrowid)
        except Exception as e :
            print("ERROR create_system():", e)
            self.db.rollback()
        return None

    def list_systems(self) -> list :
        return self._fetch_all("select * from saas_system order by id")

    def get_system_by_id(self, system_id) -> dict :
        return self._fetch_one("select * from saas_system where id = %s", (system_id,))

    def update_system(self, system_id, fields: dict) -> dict :
        sets, params = [], []
        # `order` va con backticks: es palabra reservada en MySQL.
        for col in ('name', 'visible', 'status', 'description', 'url', 'order') :
            if col in fields and fields[col] is not None :
                sets.append(f"`{col}` = %s")
                if col == 'visible' :
                    params.append(int(bool(fields[col])))
                elif col == 'order' :
                    params.append(int(fields[col]))
                else :
                    params.append(fields[col])
        if len(sets) == 0 :
            return self.get_system_by_id(system_id)
        sets.append("updated_at = %s")
        params.append(self._now())
        try :
            if self.db != None :
                params.append(system_id)
                cursor = self.db.cursor()
                cursor.execute(f"UPDATE saas_system SET {', '.join(sets)} WHERE id = %s", tuple(params))
                self.db.commit()
                return self.get_system_by_id(system_id)
        except Exception as e :
            print("ERROR update_system():", e)
            self.db.rollback()
        return None

    def disable_system(self, system_id) -> bool :
        """Baja lógica: deja el sistema en DISABLED (login lo deja de resolver)."""
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute("UPDATE saas_system SET status = %s, updated_at = %s WHERE id = %s",
                               ('DISABLED', self._now(), system_id))
                self.db.commit()
                return cursor.rowcount > 0
        except Exception as e :
            print("ERROR disable_system():", e)
            self.db.rollback()
        return False

    # ================================================================ TENANTS
    def create_tenant(self, name_company: str, razon_social: str = None,
                      contacto: str = None, mail_contacto: str = None) -> dict :
        try :
            if self.db != None :
                new_uuid = str(uuid.uuid4())
                cursor = self.db.cursor()
                sql = """INSERT INTO tenant (name_company, uuid, razon_social, contacto, mail_contacto)
                         VALUES(%s, %s, %s, %s, %s)"""
                cursor.execute(sql, (name_company, new_uuid, razon_social, contacto, mail_contacto))
                self.db.commit()
                return self.get_tenant_by_id(cursor.lastrowid)
        except Exception as e :
            print("ERROR create_tenant():", e)
            self.db.rollback()
        return None

    def list_tenants(self) -> list :
        return self._fetch_all("select * from tenant order by id")

    def get_tenant_by_id(self, tenant_id) -> dict :
        return self._fetch_one("select * from tenant where id = %s", (tenant_id,))

    def update_tenant(self, tenant_id, fields: dict) -> dict :
        sets, params = [], []
        for col in ('name_company', 'razon_social', 'contacto', 'mail_contacto') :
            if col in fields and fields[col] is not None :
                sets.append(f"{col} = %s")
                params.append(fields[col])
        if len(sets) == 0 :
            return self.get_tenant_by_id(tenant_id)
        try :
            if self.db != None :
                params.append(tenant_id)
                cursor = self.db.cursor()
                cursor.execute(f"UPDATE tenant SET {', '.join(sets)} WHERE id = %s", tuple(params))
                self.db.commit()
                return self.get_tenant_by_id(tenant_id)
        except Exception as e :
            print("ERROR update_tenant():", e)
            self.db.rollback()
        return None

    def delete_tenant(self, tenant_id) -> bool :
        """Borrado con cascada controlada en una sola transacción: desactiva contratos y
        usuarios del tenant (revocando sus tokens) y luego elimina el tenant."""
        try :
            if self.db != None :
                cursor = self.db.cursor()
                # revocar tokens de los usuarios del tenant
                cursor.execute("""delete from user_jwt where user_id in
                                  (select id from oauth where tenant_id = %s)""", (tenant_id,))
                # desactivar usuarios y contratos
                cursor.execute("UPDATE oauth SET status = %s WHERE tenant_id = %s", ('INACTIVE', tenant_id))
                cursor.execute("UPDATE tenant_contract SET status = %s WHERE tenant_id = %s", ('INACTIVE', tenant_id))
                # eliminar tenant
                cursor.execute("delete from tenant where id = %s", (tenant_id,))
                deleted = cursor.rowcount > 0
                self.db.commit()
                return deleted
        except Exception as e :
            print("ERROR delete_tenant():", e)
            self.db.rollback()
        return False

    # ============================================================== CONTRATOS
    def create_contract(self, tenant_id, system_id, status: str = 'DEMO',
                        finish_at: str = None, signature_id=None) -> dict :
        try :
            if self.db != None :
                now = self._now()
                cursor = self.db.cursor()
                sql = """INSERT INTO tenant_contract
                         (create_at, update_at, tenant_id, system_id, signature_id, signature_date, finish_at, status)
                         VALUES(%s, %s, %s, %s, %s, %s, %s, %s)"""
                cursor.execute(sql, (now, now, tenant_id, system_id, signature_id, now, finish_at, status))
                self.db.commit()
                return self.get_contract_by_id(cursor.lastrowid)
        except Exception as e :
            print("ERROR create_contract():", e)
            self.db.rollback()
        return None

    def list_contracts(self, tenant_id=None) -> list :
        if tenant_id != None :
            return self._fetch_all("select * from tenant_contract where tenant_id = %s order by id", (tenant_id,))
        return self._fetch_all("select * from tenant_contract order by id")

    def get_contract_by_id(self, contract_id) -> dict :
        return self._fetch_one("select * from tenant_contract where id = %s", (contract_id,))

    def update_contract(self, contract_id, fields: dict) -> dict :
        sets, params = ["update_at = %s"], [self._now()]
        for col in ('status', 'finish_at', 'tenant_id', 'system_id') :
            if col in fields and fields[col] is not None :
                sets.append(f"{col} = %s")
                params.append(fields[col])
        try :
            if self.db != None :
                params.append(contract_id)
                cursor = self.db.cursor()
                cursor.execute(f"UPDATE tenant_contract SET {', '.join(sets)} WHERE id = %s", tuple(params))
                self.db.commit()
                return self.get_contract_by_id(contract_id)
        except Exception as e :
            print("ERROR update_contract():", e)
            self.db.rollback()
        return None

    def deactivate_contract(self, contract_id) -> bool :
        return self.update_contract(contract_id, {"status": "INACTIVE"}) != None

    # =============================================================== USUARIOS
    def get_tenant_by_uuid(self, tenant_uuid) -> dict :
        return self._fetch_one("select * from tenant where uuid = %s", (tenant_uuid,))

    def resolve_tenant_id(self, tenant_ref) -> int :
        """Normaliza la referencia a un tenant y devuelve SIEMPRE su id numérico (o None).

        La referencia puede llegar como id numérico (consumidores que listan tenants) o
        como uuid (el claim `tenant` del JWT es el uuid). La columna oauth.tenant_id es la
        FK numérica, por lo que toda consulta debe hacerse con el id resuelto aquí."""
        if tenant_ref in (None, "") :
            return None
        if str(tenant_ref).isdigit() :
            return int(tenant_ref)
        tenant : dict = self.get_tenant_by_uuid(tenant_ref)
        return tenant['id'] if tenant != None else None

    def user_in_tenant(self, tenant_ref, username: str) -> dict :
        """Devuelve el usuario (cualquier estado) con ese username dentro del tenant, o None."""
        tenant_id = self.resolve_tenant_id(tenant_ref)
        if tenant_id == None :
            return None
        return self._fetch_one("select * from oauth where tenant_id = %s and username = %s",
                                (tenant_id, username))

    def create_user(self, tenant_ref, username: str, password: str, role: str = 'USER',
                    claims: str = None, full_name: str = None, status: str = 'ACTIVE') -> dict :
        try :
            if self.db != None :
                now = self._now()
                cursor = self.db.cursor()
                tenant_id = self.resolve_tenant_id(tenant_ref)
                if tenant_id == None :
                    print("ERROR create_user(): tenant no encontrado:", tenant_ref)
                    return None
                logging.info("create_user(%s, %s, %s, %s, %s, %s)", tenant_ref, username, role, claims, full_name, status)
                sql = """INSERT INTO oauth
                         (create_at, update_at, username, password, status, role, full_name, claims, tenant_id)
                         VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                cursor.execute(sql, (now, now, username, generate_password_hash(password),
                                     status, role, full_name, claims, tenant_id))
                self.db.commit()
                return self.clean_user(self.get_user_by_id(cursor.lastrowid))
        except Exception as e :
            print("ERROR create_user():", e)
            self.db.rollback()
        return None

    def list_users(self, tenant_ref) -> list :
        tenant_id = self.resolve_tenant_id(tenant_ref)
        if tenant_id == None :
            return []
        rows = self._fetch_all("select * from oauth where tenant_id = %s order by id", (tenant_id,))
        sessions = self.sessions_by_tenant(tenant_id)
        users : list = []
        for row in rows :
            user = self.clean_user(row)
            user["sessions"] = sessions.get(row["id"], [])
            users.append(user)
        return users

    def sessions_by_tenant(self, tenant_id) -> dict :
        """Sesiones vigentes de los usuarios del tenant, agrupadas por usuario y canal.

        Devuelve {user_id: [{channel, last_seen, online}]}. Se toma la renovación más
        reciente de cada canal: así el listado puede indicar si la persona está conectada
        desde la web, desde el móvil o desde ambos."""
        expiry = (datetime.now() - timedelta(days=self.REFRESH_EXPIRES_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        online_from = datetime.now() - timedelta(minutes=SESSION_ONLINE_MINUTES)
        rows = self._fetch_all(
            """select j.user_id, j.channel, max(j.update_at) as last_seen
               from user_jwt j join oauth o on o.id = j.user_id
               where o.tenant_id = %s and j.status = %s and j.update_at >= %s
               group by j.user_id, j.channel""",
            (tenant_id, 'ACTIVE', expiry))
        sessions : dict = {}
        for row in rows :
            last_seen = row["last_seen"]
            sessions.setdefault(row["user_id"], []).append({
                "channel": row["channel"] or 'WEB',
                "last_seen": last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen != None else None,
                "online": last_seen != None and last_seen >= online_from
            })
        return sessions

    def get_user_by_id(self, user_id) -> dict :
        return self._fetch_one("select * from oauth where id = %s", (user_id,))

    def update_user(self, user_id, fields: dict) -> dict :
        sets, params = ["update_at = %s"], [self._now()]
        for col in ('role', 'status', 'full_name', 'claims', 'username') :
            if col in fields and fields[col] is not None :
                sets.append(f"{col} = %s")
                params.append(fields[col])
        if fields.get("password") :
            sets.append("password = %s")
            params.append(generate_password_hash(fields["password"]))
        try :
            if self.db != None :
                params.append(user_id)
                cursor = self.db.cursor()
                cursor.execute(f"UPDATE oauth SET {', '.join(sets)} WHERE id = %s", tuple(params))
                self.db.commit()
                return self.clean_user(self.get_user_by_id(user_id))
        except Exception as e :
            print("ERROR update_user():", e)
            self.db.rollback()
        return None

    def deactivate_user(self, user_id) -> bool :
        """Baja lógica del usuario (status INACTIVE) y revocación de sus tokens."""
        try :
            if self.db != None :
                cursor = self.db.cursor()
                cursor.execute("UPDATE oauth SET status = %s, update_at = %s WHERE id = %s",
                               ('INACTIVE', self._now(), user_id))
                self.db.commit()
                self.delete_tokens(user_id)
                return True
        except Exception as e :
            print("ERROR deactivate_user():", e)
            self.db.rollback()
        return False

    def tenants_for_username(self, username: str) -> list :
        """Devuelve los tenants donde el username tiene una cuenta ACTIVE. Alimenta el
        combobox de 'ya soy cliente' del frontend (patrón 'encuentra tu empresa').
        Nota: `oauth` no tiene columna email; la identidad del usuario es `username`."""
        return self._fetch_all(
            """select t.id, t.name_company, t.uuid
               from oauth o join tenant t on o.tenant_id = t.id
               where o.username = %s and o.status = %s
               order by t.name_company""",
            (username, 'ACTIVE'))

    # ============================================================= ONBOARDING
    def register(self, system: dict, company: dict, admin_user: dict,
                 trial_days: int = DEMO_TRIAL_DAYS) -> dict :
        """Alta self-service en una sola transacción: crea tenant + contrato DEMO + primer
        usuario ADMIN. `system` es el dict ya resuelto (saas_system ENABLED). Devuelve
        {tenant, system, user} o None si falla (con rollback)."""
        try :
            if self.db == None :
                return None
            now = self._now()
            finish_at = (datetime.now() + timedelta(days=trial_days)).strftime("%Y-%m-%d %H:%M:%S")
            tenant_uuid = str(uuid.uuid4())
            cursor = self.db.cursor()

            cursor.execute("""INSERT INTO tenant (name_company, uuid, razon_social, contacto, mail_contacto)
                              VALUES(%s, %s, %s, %s, %s)""",
                           (company.get("name_company"), tenant_uuid, company.get("razon_social"),
                            company.get("contacto"), company.get("mail_contacto")))
            tenant_id = cursor.lastrowid

            cursor.execute("""INSERT INTO tenant_contract
                              (create_at, update_at, tenant_id, system_id, signature_date, finish_at, status)
                              VALUES(%s, %s, %s, %s, %s, %s, %s)""",
                           (now, now, tenant_id, system["id"], now, finish_at, 'DEMO'))

            cursor.execute("""INSERT INTO oauth
                              (create_at, update_at, username, password, status, role, full_name, claims, tenant_id)
                              VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                           (now, now, admin_user.get("username"),
                            generate_password_hash(admin_user.get("password")),
                            'ACTIVE', 'ADMIN', admin_user.get("full_name"),
                            admin_user.get("claims", 'RW'), tenant_id))
            user_id = cursor.lastrowid

            self.db.commit()
            return {
                "tenant": self.get_tenant_by_id(tenant_id),
                "system": system,
                "user": self.clean_user(self.get_user_by_id(user_id))
            }
        except Exception as e :
            print("ERROR register():", e)
            self.db.rollback()
        return None
