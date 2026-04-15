try:
    import logging
    import sys
    import os
    import json
    import pymysql.cursors
    from datetime import datetime
    import base64 #https://www.pycryptodome.org/src/examples#encrypt-data-with-aes

except ImportError:
    logging.error(ImportError)
    print((os.linesep * 2).join(['[Deposits] Error al buscar los modulos:', str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)

ROOT_DIR = os.path.dirname(__file__)

class Deposits() :
    db = None
    transbot_id = '1'
    

    def __init__(self) :
        try:
            host = str(os.environ.get('HOST_BD','dev.jonnattan.com'))
            port = int(os.environ.get('PORT_BD', 3306))
            user_bd = str(os.environ.get('USER_BD','----'))
            pass_bd = str(os.environ.get('PASS_BD','*****'))
            eschema = str(os.environ.get('SCHEMA_BD','*****'))
            self.db = pymysql.connect(host=host, port=port, 
                user=user_bd, password=pass_bd, database=eschema, 
                cursorclass=pymysql.cursors.DictCursor)

        except Exception as e :
            print("ERROR BD:", e)
            self.db = None

    def __del__(self):
        if self.db != None:
            self.db.close()
    def save( self, amount, name, identity, origin_bank, origin_account, date, destination_bank, destination_account ) :
        try :
            if self.db != None :
                cursor = self.db.cursor()
                sql = """INSERT INTO deposit (amount, name, transbot_id, origin_bank, destination_bank, origin_account,
                    destination_account, date_information, create_at, update_at, `identity`)
                      VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                now = datetime.now()
                cursor.execute(sql, (amount, name, self.transbot_id, origin_bank, destination_bank,
                    origin_account, destination_account, date,
                        now.strftime("%Y/%m/%d %H:%M:%S"), now.strftime("%Y/%m/%d %H:%M:%S"), identity ))
                self.db.commit()
        except Exception as e:
            print("ERROR BD:", e)
            self.db.rollback()



class Banks():
    banks = []
    json_banks = {}

    def __init__(self, root=ROOT_DIR, filename='bank/banks') :
        try:
            file_path = os.path.join(root, 'static/' + str(filename) + '.json')
            with open(file_path) as file:
                self.json_banks = json.load(file)
                file.close()
            for bank in self.json_banks['data'] :
                self.banks.append( self.process(bank) )
        except Exception as e :
            print("ERROR File:", e)
            self.banks = []
            self.json_banks = {}

    def __del__(self):
        self.banks = None
        self.json_banks = None

    def process( self, bank ) :
        name = bank['account']['bank']
        name = str(name['name'])
        account = str(bank['account']['number'])
        id = int(bank['id'])
        return Bank( id, account, name )

    def getBank(self, idBank) :
        name = None
        account = None
        for bank in self.banks :
            if bank.id == int(idBank) :
                name = bank.name
                account = bank.account
                break
        return name, account

class Bank() :
    name = ''
    account = ''
    id = -1

    def __init__(self, id, account, name) :
        self.id = id
        self.account = account
        self.name = name

    def __del__(self):
        self.name = ''
        self.account = ''
        self.id = -1

class Cipher() :
    cipher = None
    aes_key = None
    iv = b'1234567890123456'
    def __init__(self, aes_key: str = None) :
        key = os.environ.get('AES_KEY','None')
        if aes_key != None :
            key = aes_key
        self.aes_key = key.encode('utf-8')[:32]

    def __del__(self):
        self.aes_key = None
        
    def complete( self, data_str : str ) :
        response : str = data_str
        if data_str != None :
            length = len(data_str)
            resto = 16 - (length % 16)
            i = 0
            while i < resto :
                response += " "
                i += 1
        return response.encode()

    def test( self, request ) : 
        response_data = {"message":"NOk", "data": None }
        http_code = 400
        # logging.info("Reciv Header : " + str(request.headers) )
        # logging.info("Reciv " + str(request.method) )
        logging.info("Reciv Data: " + str(request.data) )
        request_data = request.get_json()
        user = request_data['user']
        passwd = request_data['password']
        clean_text = str(user) + "|||" + str(passwd)
        aes_encrypt = self.aes_encrypt( clean_text )
        logging.info("Decifrada : " + str(self.aes_decrypt( str(aes_encrypt) )) )
        if aes_encrypt != None :
            response_data = {"message":"Ok", "data": str(aes_encrypt) }
            http_code = 200
        return response_data, http_code