import socket
import ssl
import sys
sys.path.insert(0, 'graspy/')
from grasp import tprint
#this is needed becaus some wiered bug - see https://stackoverflow.com/a/29977034 and https://stackoverflow.com/a/43191101
ssl.match_hostname = lambda cert, hostname: True

hostname = '172.20.0.2'


host_addr = hostname
host_port = 443
server_sni_hostname = 'www.ap.controlware.com'
server_cert = '/usr/src/app/python/cwCA/certs/ca.cert.pem'
#server_cert = '/usr/src/app/python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem'
client_cert = '/usr/src/app/python/device@vndor1.com.cert.pem'
#client_cert = '/usr/src/app/python/cwCA/intermediate/certs/dev-ca-chain.cert.pem'
client_key = '/usr/src/app/python/Dev1234.key.pem'
devID_cert = '/usr/src/app/python/vendorCA/8021ARintermediate/certs/Dev1234.cert.pem'


from cbor import dumps, loads
#import json


import secrets # for nonce
from datetime import datetime, date # for timestamp

import OpenSSL.crypto
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


#pubKey = cert.get_pubkey()
#pubKeyString = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,pubKey)

#print(type(cert))

import threading
from queue import Queue

class TLS_device_Thread(threading.Thread):
    def __init__(self, queue, kwargs=None):
        threading.Thread.__init__(self, kwargs=None)
        self.queue = queue
        self.daemon = True

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

    def handle(self, conn, byte_voucher):
        #conn.write(b'GET / HTTP/1.1\n')
        conn.write(byte_voucher)
        print(conn.recv().decode())

    def run(self):

        while True:
            tmpIP = self.queue.get()
            tprint(tmpIP)
            if tmpIP:
                devIDcertString = self.getCertStringfromFile(devID_cert)
                #nonce = gen_nonce(50)
                nonce = secrets.token_hex(32)
                timestamp = datetime.now().isoformat()
                time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f")



                request = {
                  "created-on": timestamp,
                  "nonce": nonce,
                  "devID": devIDcertString
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

                # convert into JSON:
                #y = json.dumps(x)

                # the result is a JSON string:
                #print(y)
                byte_voucher = dumps(voucher_request)
                #print (byte_voucher)
                '''
                test = loads(byte_voucher)
                #print(type(test), test)
                request = loads(test["request"])
                print(request["nonce"])
                print(request["created-on"])

                #from cbor2 import dumps, loads

                exit()
                '''
                HOST, PORT = '172.20.0.2', 443
                #context = ssl.create_default_context()



                sock = socket.socket(socket.AF_INET)
                #context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                context.load_verify_locations('/usr/src/app/python/ca.cert.pem')
                context.verify_mode = ssl.CERT_REQUIRED
                context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
                conn = context.wrap_socket(sock, server_hostname=HOST)

                try:
                    conn.connect((HOST, PORT))
                    self.handle(conn, byte_voucher)
                finally:
                    conn.close()
