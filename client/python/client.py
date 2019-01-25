#client for netconf
from netconf.client import NetconfSSHSession
from lxml import etree
import netconf.util as util
from netconf import nsmap_add, nsmap_update
from netconf import NSMAP

import re
#print(cert.serial_number)
#print(cert)
print("\n\n\n\n\n")
certfile = '/usr/src/app/ca/8021ARintermediate/certs/Device1234.cert.pem'


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

    #print(ctx)




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

class bootstrapInformation(univ.Sequence):
   componentType = namedtype.NamedTypes(
       namedtype.NamedType('id', univ.Integer()),
       namedtype.NamedType('os-name', univ.OctetString()),
       namedtype.NamedType('os-version', univ.OctetString()),
       namedtype.NamedType('download-uri', univ.OctetString()),
       namedtype.NamedType('hash-algorithm', univ.OctetString()),
       namedtype.NamedType('hash-value', univ.OctetString()),
       namedtype.NamedType('configuration-handling', univ.OctetString()),
       namedtype.NamedType('pre-configuration-script', univ.OctetString()),
       namedtype.NamedType('configuration', univ.OctetString()),
       namedtype.NamedType('post-configuration-script', univ.OctetString())
   )

zKey = bootstrapInformation()
zKey['id'] = 123
zKey['os-name'] = 'IOS XE'
zKey['os-version'] = '16.6.6'
zKey['download-uri'] = "www.fileserver.controlware.de"
zKey['hash-algorithm'] = 'md5'
zKey['hash-value'] = '123456'
zKey['configuration-handling'] = 'merge'
zKey['pre-configuration-script'] = 'pre.py'
zKey['configuration'] = 'tbd'
zKey['post-configuration-script'] = 'post.py'


substrate = encode(zKey)
print (type(substrate), substrate)

from base64 import (
    b64encode,
    b64decode,
)

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


#pubKey = cert.get_pubkey()
#pubKeyString = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,pubKey)

#print(type(cert))

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

def test():
    chain_file = '/usr/src/app/ca/certs/ca.cert.pem'
    chain_file = '/usr/src/app/ca/8021ARintermediate/certs/ca-chain.cert.pem'
    result = verify_certificate_chain(certfile ,chain_file)
    if result:
        print('Certificate validated')
    #exit()

    cert = OpenSSL.crypto.load_certificate(
          OpenSSL.crypto.FILETYPE_PEM,
          getCertStringfromFile(certfile)
    )


    sign = signString ("/usr/src/app/python/cwCA/intermediate/private/intermediate.key.pem",b"password", substrate, "sha256" )
    verifyString('/usr/src/app/python/cwCA/intermediate/certs/intermediate.cert.pem', sign, substrate,"sha256")

'''
teststring = "HalloTest123"
test_sign = signString ("/usr/src/app/python/cwCA/intermediate/private/intermediate.key.pem", b"password", teststring.encode('ascii'), "sha256" )
verifyString('/usr/src/app/python/cwCA/intermediate/certs/intermediate.cert.pem', test_sign, teststring.encode('ascii'),"sha256")
#print (type(sign), sign)
data_base64 = base64.b64encode(test_sign)
#verifyString('/usr/src/app/python/cwCA/intermediate/certs/intermediate.cert.pem', data_base64, substrate,"sha256")
#print (type(data_base64), data_base64)
test64 = base64.b64decode(data_base64)
#print (type(test64), test64)
verifyString('/usr/src/app/python/cwCA/intermediate/certs/intermediate.cert.pem', test64, teststring.encode('ascii'),"sha256")
'''

received_record, _ = decode(substrate, asn1Spec=bootstrapInformation())
#print (type(received_record))
#print ("received: ", received_record)
for field in received_record:
    print('{}   \t- {}'.format(field, received_record[field]))

#print(base64.encodebytes(substrate))


exit()
'''
received_record, _ = decode(substrate, asn1Spec=ZKey())
#print (type(received_record))
#print ("received: ", received_record)
for field in received_record:
    print('{}   \t- {}'.format(field, received_record[field]))

print(base64.encodebytes(substrate))
'''
#exit()
nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")
MODEL_NS = "urn:my-urn:my-model"
nsmap_add('pfx', MODEL_NS)
#nsmap_update({'pfx': MODEL_NS})

keyFileToSend = "python/cwCA/intermediate/certs/www.ap.controlware.com.cert.pem"
privateKeyFile = "/usr/src/app/python/vendorCA/intermediate/private/www.ownership.vendor1.com.key.pem"

fileString = getCertStringfromFile(keyFileToSend)

sign = signString (privateKeyFile ,b"password", fileString.encode('ascii'), "sha256" )

#Encode signature so it can be send as a string
sign_base64 = base64.b64encode(sign)
utf8Signature = sign_base64.decode('utf-8')
if verifyString('/usr/src/app/python/vendorCA/intermediate/certs/www.ownership.vendor1.com.cert.pem', sign, fileString.encode('ascii'),"sha256"):
    ownershipRPC = util.elm("ownership")
    ownerCertificate = util.subelm(ownershipRPC, "ownerCertificate")
    ownerCertificate.append(util.leaf_elm("certificate", fileString))
    #ownerCertificate.append(util.leaf_elm("certificateSignature", sign_base64))
    ownerCertificate.append(util.leaf_elm("certificateSignature", utf8Signature))

#print(etree.tounicode(ownershipRPC, pretty_print=True))
#exit()

session = NetconfSSHSession("172.17.0.3", "8300", "admin", "admin", debug=True)
#reply = session.get_config()
#root, reply, replystring = session.send_rpc("<my-cool-rpc/>")

#root, reply, replystring = session.send_rpc("<bootstrap/>")
root, reply, replystring = session.send_rpc(ownershipRPC)

session.close()
'''
reply_list = list(reply)
for e in reply_list:
    print (e.tag, e.attrib, e.text)
print("\n")
dataElem = reply_list[0]
'''
dataElem = reply.find("nc:data", namespaces=NSMAP)
x = dataElem.find("nc:result", namespaces=NSMAP)
if x is not None:
    print(x.text)
else:
    print("not found")

'''
print("\n")
f = reply.xpath("//nc:data/nc:result", namespaces=NSMAP )
#print(f, type(f))
for ff in f:
    print(ff.text)
'''
'''
for e in root.iter():
    print (e.text)
'''

exit()
#datanode = util.elm("datasdaa")
#x = util.filter_list_iter(inputnode, reply)
#print(x)
#print (etree.tounicode(resultnode))

exit()
xml = etree.tounicode(root)
print (xml)
xml = re.sub(' xmlns="[^"]+"', '', xml, count=1)
#data = etree.fromstring(xml.replace(' ', '').replace('\n', ''))
data = etree.fromstring(xml)
for devs in data.iter('result'):
    print(devs.text)

print("\n\n")
"""
data = util.elm("nc:data")
sysc = util.subelm(data, "sys:system")
sysc.append(util.leaf_elm("sys:hostname", "test"))
#print(etree.tounicode(data))

print(NSMAP)
xml = etree.tounicode(root)
#print (xml)
path = './/nc:*/*/pfx:result'

t = root.xpath('pfx:result', namespaces=NSMAP)
print(t)

result = util.xpath_filter_result(reply, "nc:rpc-reply/nc:data/pfx:result")
#print (result.tag, result.attrib, result.text )
print(etree.tounicode(result))

test = root.iterfind(path, namespaces=NSMAP)

#print ("find: ", type(test))
for i in test:
    print ("-",i)

test = root.find(path, namespaces=NSMAP)
print(test)
test2 = root.findall("path", namespaces=NSMAP)
print(test2)
"""
"""
data = util.elm("bootstrap")

with open(certfile, 'r') as myfile:
    fileString=myfile.read()#.replace('\n', '')
myfile.close()

certInfo = util.subelm(data, "certificate-information")
certInfo.append(util.leaf_elm("certificate", fileString))
onboard = util.subelm(data, "onboarding-information")

redirect = util.subelm(data, "redirect-information")
boots_server = util.subelm(redirect, "bootstrap-server")
boots_server.append(util.leaf_elm("address", "172.17.0.1"))
boots_server.append(util.leaf_elm("port", "8300"))
boots_server.append(util.leaf_elm("trust_anchor", "undefined"))


boot_img = util.subelm(onboard, "boot-image")
boot_img.append(util.leaf_elm("os-name", "IOS"))
boot_img.append(util.leaf_elm("os-version", "16.8"))
boot_img.append(util.leaf_elm("download-uri", "tftp://10.0.0.1/files"))
img_verification = util.subelm(boot_img, "image-verification")
img_verification.append(util.leaf_elm("hash-algorithm", "md5"))
img_verification.append(util.leaf_elm("hash-value", "12345678"))

onboard.append(util.leaf_elm("configuration-handling", "append"))
onboard.append(util.leaf_elm("pre-configuration-script", "pre.py"))
onboard.append(util.leaf_elm("configuration", "tbd"))
onboard.append(util.leaf_elm("post-configuration-script", "post.py"))
"""
