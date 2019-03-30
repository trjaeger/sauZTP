# -*- coding: utf-8 eval: (yapf-mode 1) -*-


#client for netconf
from netconf.client import NetconfSSHSession
from lxml import etree
import netconf.util as util
from netconf import nsmap_add, nsmap_update
from netconf import NSMAP
import logging
import re

from cbor import dumps, loads #cbor


certfile = '/usr/src/app/ca/8021ARintermediate/certs/Device1234.cert.pem'

logging.basicConfig(level=logging.INFO)
logging.info('STARTING NETCONF CLIENT')
import OpenSSL.crypto
from asn1crypto import pem

def getCertStringfromFile(filepath):
    with open(filepath, 'r') as myfile:
        fileString=myfile.read()#.replace('\n', '')
    myfile.close()
    return fileString

def parse_chain(chain):
    _PEM_RE = re.compile(b'-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?\n?', re.DOTALL)
    return [c.group() for c in _PEM_RE.finditer(chain)]

def verify_certificate_chain(certfile, chain_file):
    #with open('/usr/src/app/ca/8021ARintermediate/certs/ca-chain.cert.pem', 'rb') as f:

    with open(chain_file, 'rb') as f:
        chain_cert = f.read()
    f.close()
    client_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, getCertStringfromFile(certfile))
    #print(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, client_cert).decode("utf-8"))

    root_certs = []
    for cr in parse_chain(chain_cert):
        root_certs.append(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cr))
    try:
        store = OpenSSL.crypto.X509Store()
        for rc in root_certs:
            store.add_cert(rc)
            #print(rc)
            #print(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, rc).decode("utf-8"))

        ctx = OpenSSL.crypto.X509StoreContext(store, client_cert)
        ctx.verify_certificate()
        return True

    except Exception as e:
        print(e)
        return False

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

def verifyString(certFilePath, sign, stringToVerify, algo):
    cert = OpenSSL.crypto.load_certificate(
          OpenSSL.crypto.FILETYPE_PEM,
          getCertStringfromFile(certFilePath)
    )
    try:
        result = OpenSSL.crypto.verify(cert, sign, stringToVerify , algo)
        #print("signature verified")
        return True
    except Exception as e:
        print(e)
        print("verify failed")
        return False
#validator = CertificateValidator(end_entity_cert)
#certByteString = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert)
#print (certByteString.decode("utf-8") )

#print("\n\n\n\n\n")
#print(fileString)

#print (certByteString.decode("utf-8") )
#print (certByteString)

from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
import base64

def buildbootstrapArtifact():
    bootstrapArtifact = {
        "bootstrap−information" : {
            "id": '123',
            "boot-image": {
                "name": 'IOS XE',
                "os-version": '16.6.6',
                "download-uri": 'IOS XE',
                "verification": {
                    "hash-algorithm": 'SHA-256',
                    "hash-value": '123456ABCD',
                }
                },
            "configuration-handling": 'IOS XE',
            "pre-configuration-script": {
                "filename": 'pre.py',
                "interpreter": 'python',
                "download-uri": 'www.fileserver.controlware.de/pre.py',
                "verification": {
                    "hash-algorithm": 'SHA-256',
                    "hash-value": '123456ABCD',
                }
            },
            "configuration": 'IOS XE',
            "post-configuration-script": {
                "filename": 'post.py',
                "interpreter": 'python',
                "download-uri": 'www.fileserver.controlware.de/post.py',
                "verification": {
                    "hash-algorithm": 'SHA-256',
                    "hash-value": '123456ABCD',
                }
            }
        }
    }
    return dumps(bootstrapArtifact)
    #bytebootstrapArtifact = dumps(bootstrapArtifact)
    #print(bytebootstrapArtifact)

from base64 import (
    b64encode,
    b64decode,
)

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA





def main(args):

    if not args:
        return
    #print(type(args))
    #return

    #TODO: check if args is a valid IP

    nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")
    MODEL_NS = "urn:my-urn:my-model"
    nsmap_add('pfx', MODEL_NS)

    keyFileToSend = "python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem"
    privateKeyFile = "/usr/src/app/python/vendorCA/intermediate/private/www.ownership.vendor1.com.key.pem"

    fileString = getCertStringfromFile(keyFileToSend)

    sign = signString (privateKeyFile ,b"password", fileString.encode('ascii'), "sha256" )

    #Encode signature so it can be send as a string
    sign_base64 = base64.b64encode(sign)
    utf8Signature = sign_base64.decode('utf-8')
    ownershipRPC = util.elm("ownership")
    cert = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        getCertStringfromFile('/usr/src/app/python/vendorCA/intermediate/certs/www.ownership.vendor1.com.cert.pem')
    )
    #if verifyString(cert, sign, fileString.encode('ascii'),"sha256"):
    if verifyString('/usr/src/app/python/vendorCA/intermediate/certs/www.ownership.vendor1.com.cert.pem', sign, fileString.encode('ascii'),"sha256"):
        ownerCertificate = util.subelm(ownershipRPC, "ownerCertificate")
        ownerCertificate.append(util.leaf_elm("certificate", fileString))
        #ownerCertificate.append(util.leaf_elm("certificateSignature", sign_base64))
        ownerCertificate.append(util.leaf_elm("certificateSignature", utf8Signature))

    bootstrapRPC = util.elm("bootstrap")
    bootInfo  = util.subelm(bootstrapRPC, "bootInfo")

    #bootInfo_base64 = base64.b64encode(asnString)
    bytebootstrapArtifact = buildbootstrapArtifact()
    bootInfo_base64 = base64.b64encode(bytebootstrapArtifact)
    utf8BootInfo = bootInfo_base64.decode('utf-8')

    privateKeyFile = "/usr/src/app/python/cwCA/intermediate/private/www.ap.controlware.com.key.pem"
    sign = signString (privateKeyFile ,b"password", utf8BootInfo.encode('ascii'), "sha256" )
    sign_base64 = base64.b64encode(sign)
    utf8Signature = sign_base64.decode('utf-8')

    bootInfo.append(util.leaf_elm("bootInfoASN", utf8BootInfo))

    if verifyString('/usr/src/app/python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem', sign, utf8BootInfo.encode('ascii'),"sha256"):
        bootInfo.append(util.leaf_elm("bootInfoSignature", utf8Signature))

    #TODO: not hardcode
    session = NetconfSSHSession(args, "8300", "admin", "admin", debug=True)
    root, reply, replystring = session.send_rpc(ownershipRPC)
    root, reply, replystring = session.send_rpc(bootstrapRPC)
    session.close()



    dataElem = reply.find("nc:data", namespaces=NSMAP)
    x = dataElem.find("nc:result", namespaces=NSMAP)
    if x is not None:
        print(x.text)
    else:
        print("not found")

if __name__ == '__main__':
    import sys
    print(sys.argv[1:])
    #main(sys.argv[1:])
