#!/usr/bin/env python
from flask import Flask, json, request
from cbor import dumps, loads
import OpenSSL.crypto

from datetime import datetime, date # for timestamp

import base64


from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
app = Flask(__name__)

def signString(keyFilePath, password, stringToSign, algo):
    key_file = open(keyFilePath, "r")
    key = key_file.read()
    key_file.close()

    if key.startswith('-----BEGIN '):
        pkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key, password)
    else:
        pkey = OpenSSL.crypto.load_pkcs12(key, password).get_privatekey()

    sign = OpenSSL.crypto.sign(pkey, stringToSign, algo)

    return sign # return signature


def simulateMASA():
    keyFileToSend = "python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem"
    privateKeyFile = "/usr/src/app/python/vendorCA/intermediate/private/www.ownership.vendor1.com.key.pem"
    fileString = getCertStringfromFile(keyFileToSend)
    sign = signString (privateKeyFile ,b"password", fileString.encode('ascii'), "sha256" )

    #Encode signature so it can be send as a string
    sign_base64 = base64.b64encode(sign)
    utf8Signature = sign_base64.decode('utf-8')


    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        getCertStringfromFile('/usr/src/app/python/vendorCA/intermediate/certs/www.ownership.vendor1.com.cert.pem')
    )
    if verifyString(cert, sign, fileString.encode('ascii'),"sha256"):
        return fileString, utf8Signature
    else:
        print("\treturning none")
        return None

def buildVoucher(nonce):
    #fileString, utf8Signature = simulateMASA()
    masa = simulateMASA()

    fileString = masa[0]
    utf8Signature = masa[1]
    if masa:
        print('building vocher')
        #print(type(masa))

        timestamp = datetime.now().isoformat()

        #this voucher is very lazy, but all I need for now, see bootom of this file for full YANG Module
        voucher = {
          "created-on": timestamp,
          "nonce": nonce,
          "pinned-domain-cert": fileString,
          "signature": utf8Signature
        }
        return dumps(voucher)
    else:
        return " "

#unessesary, just to have a standard route
@app.route('/')
def hello_world():
    return 'Hey, this Server doas some Zero Touch provisioning'


#check if a String matches its signature
def verifyString(cert, sign, stringToVerify, algo):
    try:
        OpenSSL.crypto.verify(cert, sign, stringToVerify , algo)
        print("signature verified")
        return True
    except Exception as e:
        print(e)
        print("verify failed")
        return False

#load a a certificate from a file an return it as a string
def getCertStringfromFile(filepath):
    with open(filepath, 'r') as myfile:
        fileString=myfile.read()#.replace('\n', '')
    myfile.close()
    return fileString

@app.route('/requestvoucher',methods=['POST'])
def voucher():

    #print(request.data)
    #print(request.args.get('summary'))
    #print(request.args)

    #jsonstring = request.data.decode('utf8').replace("'", '"')
    #data = json.loads(jsonstring)
    #print(json.dumps(data, indent=4))

    #print(request.values)
    #print(request.form['summary'])
    tmp_voucher = loads(request.data)
    #print(type(test), test)
    if 'voucher-request' not in tmp_voucher:
        print("cant handle msg")
    else:
        voucher = tmp_voucher['voucher-request']
        #print(voucher["request"])
        #print(voucher["signature"])
        request_artifact = loads(voucher["request"])
        #print(request_artifact)
        nonce = request_artifact["nonce"]

        """
        here you would check if the voucher["serial-number"] field matches ones of the devices you know
        then go look up the devices certificate and verify the signature
        """
        manufacturerCert = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            #request_artifact["devID"]  #lazy way just take cert from the message
            getCertStringfromFile('/usr/src/app/python/vendorCA/8021ARintermediate/certs/Dev1234.cert.pem')
        )


        if verifyString(manufacturerCert, voucher["signature"], voucher["request"], "sha256"):
            voucher = buildVoucher(nonce)
            return voucher

    return json.jsonify({'Error': "888888"})
    #return request.data

    #return json.jsonify({'Voucher': "dies ist ein Voucher"})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

################################################################################
########################### Appendix ###########################################
################################################################################
# YANG Module by https://tools.ietf.org/html/draft-ietf-anima-voucher-07#page-9
#   yang-data voucher-artifact:
#     +---- voucher
#        +---- created-on                       yang:date-and-time
#        +---- expires-on?                      yang:date-and-time
#        +---- assertion                        enumeration
#        +---- serial-number                    string
#        +---- idevid-issuer?                   binary
#        +---- pinned-domain-cert               binary
#        +---- domain-cert-revocation-checks?   boolean
#        +---- nonce?                           binary
#        +---- last-renewal-date?               yang:date-and-time
