import requests
from queue import Queue
import threading

import secrets # for nonce
from datetime import datetime, date # for timestamp
from cbor import dumps, loads #cbor

import OpenSSL.crypto

#url = 'http://172.20.0.3:5000/requestvoucher'
#resp = requests.get(url)
#if resp.status_code != 200:
#    # This means something went wrong.
#    raise
#print(resp.json())

devID_cert = '/usr/src/app/python/vendorCA/8021ARintermediate/certs/Dev1234.cert.pem'
client_key = '/usr/src/app/python/Dev1234.key.pem'

class REST_device_Thread(threading.Thread):
    def __init__(self, queue, kwargs=None):
        threading.Thread.__init__(self, kwargs=None)
        self.queue = queue


    def getCertStringfromFile(self, filepath):
        with open(filepath, 'r') as myfile:
            fileString=myfile.read()#.replace('\n', '')
        myfile.close()
        return fileString

    def signString(self, keyFilePath, password, stringToSign, algo):
        #key_file = open(keyFilePath, "r")
        #key = key_file.read()
        #key_file.close()
        key = self.getCertStringfromFile(keyFilePath)

        if key.startswith('-----BEGIN '):
            pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key, password)
        else:
            pkey = OpenSSL.crypto.load_pkcs12(key, password).get_privatekey()

        sign = OpenSSL.crypto.sign(pkey, stringToSign, algo)

        return sign # return signature

    def run(self):

        while True:
            tmpIP = self.queue.get()
            #tprint(tmpIP)
            if tmpIP:
                devIDcertString = self.getCertStringfromFile(devID_cert)
                #nonce = gen_nonce(50)
                nonce = secrets.token_hex(32)
                timestamp = datetime.now().isoformat()
                time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")



                request = {
                  "created-on": timestamp,
                  "nonce": nonce,
                  "devID": devIDcertString,
                  "Serial Number": "JADA123456789"
                }
                byteRequest = dumps(request)
                sign = self.signString (client_key , b'password',byteRequest, "sha256" )
                print(sign)
                voucher_request = {
                    "voucher-request" : {
                    "request": byteRequest,
                    "signature": sign
                    }
                }

                url = 'http://' + tmpIP + ':5000/requestvoucher'
                byte_voucher = dumps(voucher_request)

                responseBytes = requests.post(url, data=byte_voucher, stream=True)
                if responseBytes.status_code != 200:
                    print('ERROR')
                    raise

                response = loads(responseBytes.raw.read())

                """
                verify this zertifikate and signature with the internal trust store
                """
                print(response['pinned-domain-cert'])
