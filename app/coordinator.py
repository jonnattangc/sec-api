#!/usr/bin/python

try:
    import logging
    import sys
    import os
    import requests
    import time
    import json
    from datetime import datetime, timedelta
    from utils import Banks
except ImportError:
    logging.error(ImportError)
    print((os.linesep * 2).join(['[coordinator] Error al buscar los modulos:',
       str(sys.exc_info()[1]), 'Debes Instalarlos para continuar', 'Deteniendo...']))
    sys.exit(-2)

############################# Configuraci'on de Coordinador ################################

class Coordinator() :
    db = None
    host = os.environ.get('HOST_BD','None')
    user = os.environ.get('USER_BD','None')
    password = os.environ.get('PASS_BD','None')
    token_bearer = os.environ.get('BEARER_MIDDLEWARE','None')
    # URL notificacion a middleware IONIX
    url_notification = str(os.environ.get('NOTIFICATION_URL','None')) + '/deposits'

    transbot_id = -1

    def __init__(self) :
        try:
            self.transbot_id = int(os.environ.get('TRANSBOT_ID','-1'))
        except Exception as e :
            print("ERROR __init__:", e)

    # Evalua la fecha de 
    def getEvaluateDates(self, id_bank ) :
        banks = Banks()
        name, account = banks.getBank( id_bank )
        del banks
        
        now = datetime.now()
        yesterday = now - timedelta(1) 
        initial_date = yesterday.strftime("%d/%m/%Y")

        if( name != None and account != None ) :
            cursor = self.db.cursor()
            try:
                sql = """SELECT d.date_information as date FROM deposits.deposit d WHERE d.destination_account = %s ORDER BY d.date_information DESC limit 1"""
                cursor.execute(sql, (str(account)))
                results = cursor.fetchall()
                for row in results:
                    date_bd = str(row['date'])
                    from_date = datetime.strptime(date_bd, '%Y-%m-%d %H:%M:%S')
                    initial_date = from_date.strftime("%d/%m/%Y")
            except Exception as e:
                    print("ERROR BD:", e)

        logging.info(str(name) + '[' + str(id_bank) + ']: ' + str(account) )
        
        data = {
            "status": "success",
            "deposits": {
                "from_date" : initial_date,
                "to_date"   : now.strftime("%d/%m/%Y")
            },
        }
        return data

    def notify_middleware( self, deposit, account, id_bank ) : 
        request_tx = {
            'data': {
                'transbotID'    : self.transbot_id,
                'amount'        : int(deposit.amount),
                'name'          : deposit.origin_name.upper(),
                'identity'      : deposit.identity,
                'bank'          : deposit.origin_bank.upper(),
                'account'       : deposit.origin_account.upper(),
                'date'          : deposit.date_registry.upper(),
                'bank_account'  : account, # cuenta banco destino del deposito
            },
            'bank': id_bank
        }
        logging.info("Request to Middleware: " + str(request_tx) )
        response = {}
        try :
            headers_tx = {'Content-Type': 'application/json','Authorization': 'Bearer ' + str(self.token_bearer) }
            response = requests.post(self.url_notification, json = request_tx, headers = headers_tx, timeout = 20)
        except Exception as e:
            print("ERROR POST:", e)
        if response.status_code != None and response.status_code == 200 :
            data_response = response.json()
            logging.info("Response : " + str( data_response ) )

    # Procesa dato que llega desde Bot
    def process_update(self, deposit_bank_name, deposit_bank_account, deposit_bank_internal_id, deposits ) :
        logging.info('Cuenta [' + deposit_bank_internal_id + '] del ' + deposit_bank_name + ' N°: ' + deposit_bank_account )
        status = 'success'
        for deposit in deposits :
            logging.info('Deposito ' + str(deposit) )
            cursor = self.db.cursor()
            data = Deposit( deposit )
            self.notify_middleware( data, deposit_bank_account, deposit_bank_internal_id )
            del data
        return  {"status": str(status)}

    def proccess_solicitude( self, request , subpath : str) :
        m1 = time.monotonic_ns()
        dataTx = {}
        http_code = 200
        paths = subpath.split('/')
        if len(paths) >= 3 and subpath.find('dreams') < 0 :
            logging.info('paths[2]: ' + str(paths[2]) )
            if paths[2].find('bank_dates') >= 0 :
                id = req.args.get('id', '-1')
                dataTx =  self.getEvaluateDates( id )
            elif paths[2].find('bank_deposits_update') >= 0 :
                request_data = req.get_json()
                id_bank = str(request_data['platform_bank_id'])
                banks = Banks()
                name, account = banks.getBank( id_bank )
                del banks
                if name != None and account != None :
                    dataTx = self.process_update( str(name), str(account), id_bank, request_data['deposits'] )
                else: 
                    dataTx =  {
                        "status": "error"
                     }
            elif paths[2].find('ping') >= 0 :
                dataTx =  {}
            else : # otras notificaciones
                dataTx =  {
                    "status": "success"
                }
        else :
            if subpath.find('dreams') >= 0 :
                #logging.info("################ DREAMS Reciv Action: " + str(subpath) )
                #logging.info("Reciv H : " + str(request.headers) )
                #logging.info("Reciv D: " + str(request.data) )
                m1 = time.monotonic()
                diff = 0
                request_data = request.get_json()
                url = os.environ.get('SLACK_NOTIFICATION','None')
                headers = {'Content-Type': 'application/json'}
                response = None
                request_tx = {}

                if str(subpath).find('deposito') >= 0 :
                    monto = str(request_data['amount'])
                    fecha = str(request_data['date'])
                    name = str(request_data['name'])
                    rut = str(request_data['identity'])
                    bank = str(request_data['bank'])
                    account = str(request_data['account'])
                    code = str(request_data['code'])

                    request_tx = {
                            'username': 'OJO: Notificación de depósito',
                            'text': 'Deposito de $' + monto + ' recibido a las ' + fecha,
                            'attachments': [
                                {
                                    'fallback'      : 'Nuevo deposito',
                                    'pretext'       : 'Datos de Origen',
                                    'text'          : 'Nombre: ' + name,
                                    'color'         : 'good',
                                    'fields'        : [
                                        {
                                            'title': 'Rut',
                                            'value': rut,
                                            'short': True
                                        },{
                                            'title': 'Banco',
                                            'value': bank,
                                            'short': True
                                        },{
                                            'title': 'Cuenta',
                                            'value': account,
                                            'short': True
                                        },{
                                            'title': 'Código',
                                            'value': code,
                                            'short': True
                                        }
                                    ]
                                }
                            ]
                        }
                else :
                    error_msg = 'Favor cambiar url !!! \n' + str(request_data['message'])
                    request_tx = {
                            'username': '[jonnattan.com]: Notificación Recibida',
                            'text': error_msg,
                        }

                try :
                    logging.info("URL : " + url )
                    if url != 'None' :
                        response = requests.post(url, data = json.dumps(request_tx), headers = headers, timeout = 40)
                        diff = time.monotonic() - m1;
                        http_code = response.status_code 
                        if( response != None and response.status_code == 200 ) :
                            logging.info('Response Slack' + str( response ) )
                        elif( response != None and response.status_code != 200 ) :
                            logging.info("Response NOK" + str( response ) )
                        else :
                            logging.info("Nose pudo notificar por Slak")
                except Exception as e:
                    print("ERROR POST:", e)

                logging.info("Time Response in " + str(diff) + " sec.")
                return dataTx, http_code
            else: 
                # logging.info("Reciv H : " + str(request.headers) )
                banks = Banks()
                data = banks.json_banks
                del banks
        logging.info("Response time " + str(time.monotonic_ns() - m1) + " ns")
        return dataTx, http_code

class Deposit() :

    origin_bank = None 
    origin_account = None 
    date_registry = None 
    amount = None 
    origin_name = None 
    identity = None 
    internal_bot_process = None 
    channel = None 
    origin_rut = None 
    destination_rut = None 
    description = None 
    balance = None 
    comment = None 
    type_mov = None 


    def __init__(self, deposit ) :
        self.process( deposit )

    def __del__(self):
        self.origin_bank = None 
        self.origin_account = None 
        self.date_registry = None 
        self.amount = None 
        self.origin_name = None 
        self.identity = None 
        self.internal_bot_process = None 
        self.channel = None 
        self.origin_rut = None 
        self.destination_rut = None 
        self.description = None 
        self.balance = None 
        self.comment = None 
        self.type_mov = None 

    def process(self, deposit ) :
        try : 
            self.origin_bank = deposit['origin_bank']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)
        
        try : 
            self.origin_account = deposit['origin_account']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.date_registry = deposit['date']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.amount = deposit['amount']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.origin_name = deposit['origin_name']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.identity = deposit['identity']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.internal_bot_process = deposit['internal_bot_process']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.channel = deposit['channel']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.origin_rut = deposit['origin_rut']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.destination_rut = deposit['destination_rut']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.description = deposit['description']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.balance = deposit['balance']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)

        try : 
            self.comment = deposit['comment']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)
        
        try : 
            self.type_mov = deposit['type']
        except Exception as e:
            print("ERROR, No se encuentra: ", e)
