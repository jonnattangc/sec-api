try:
    import logging
    import sys
    import os
    import time
    import json
    import requests
    import pymysql.cursors
    from datetime import datetime, timedelta
    from utils import Banks
    import psutil

except ImportError:

    logging.error(ImportError)
    print((os.linesep * 2).join(['[check] Error al buscar los modulos:', str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)

class Checker() :
    db = None
    def __init__(self) :
        try:
            host : str = os.environ.get('HOST_BD', None)
            port : int = int(os.environ.get('PORT_BD', -1))
            user_bd : str = os.environ.get('USER_BD', None )
            pass_bd : str = os.environ.get('PASS_BD', None)
            eschema : str = os.environ.get('SCHEMA_BD', None)
            
            self.db = pymysql.connect(host=host, port=port, 
                user=user_bd, password=pass_bd, database=eschema, 
                cursorclass=pymysql.cursors.DictCursor)

        except Exception as e :
            print("ERROR BD:", e)
            self.db = None

    def __del__(self):
        if self.db != None:
            self.db.close()

    def is_connect(self) :
        version = 'Desconocida'
        if  self.db != None :
            try :
                logging.info('Se ha conectado a la BD') 
                cursor = self.db.cursor()
                sql = """select version() as version"""
                cursor.execute(sql, ())
                results = cursor.fetchall()
                for row in results:
                    version = row['version']
                    logging.info('Version BD: ' + str(version))
                cursor.close()
            except Exception as e:
                print("ERROR is_connect():", e)
        return version

    def get_info(self) :
        m1 = time.time()
        logging.info("Check Status Gral" )
        version_bd = self.is_connect()
        memoria = psutil.virtual_memory()
        disco = psutil.disk_usage('/')

        data = {
            'Memoria': {
                'Total'      : f"{memoria.total / (1024**3):.2f} GB",
                'Disponible' : f"{memoria.available / (1024**3):.2f} GB",
                'Utilizada'  : f"{memoria.used / (1024**3):.2f} GB, {memoria.percent}%",
            },
            'Disco': {
                'Total'      : f"{disco.total / (1024**3):.2f} GB",
                'Disponible' : f"{disco.free / (1024**3):.2f} GB",
                'Utilizada'  : f"{disco.used / (1024**3):.2f} GB, {disco.percent}%",
            },
            'CPU' : {
                'Cores' : psutil.cpu_count(logical=False),
                'Total' : psutil.cpu_count(logical=True)
            },
            'Database' : {
                'NAME'     : 'MySQL',
                'Version'    : version_bd,
            },
            'Uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time()))
        }
        m2 = time.time()
        time_response = str(m2 - m1)
        logging.info("Response in " + time_response)
        return data


