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


from certvalidator import CertificateValidator, errors
import OpenSSL.crypto
from asn1crypto import pem






def parse_chain(chain):
    _PEM_RE = re.compile(b'-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?\n?', re.DOTALL)
    return [c.group() for c in _PEM_RE.finditer(chain)]

def verify_certificate_chain(certfile, chain_file):
    with open(certfile, 'rb') as f:
        end_entity_cert = f.read()

    #with open('/usr/src/app/ca/8021ARintermediate/certs/ca-chain.cert.pem', 'rb') as f:

    with open(chain_file, 'rb') as f:
        chain_cert = f.read()

    client_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, end_entity_cert)
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

chain_file = '/usr/src/app/ca/certs/ca.cert.pem'
chain_file = '/usr/src/app/ca/8021ARintermediate/certs/ca-chain.cert.pem'
result = verify_certificate_chain(certfile ,chain_file)
if result:
    print('Certificate validated')
exit()


end_entity_cert = None
intermediates = []

with open('/usr/src/app/ca/8021ARintermediate/certs/ca-chain.cert.pem', 'rb') as f:
    for type_name, headers, der_bytes in pem.unarmor(f.read(), multiple=True):
        if end_entity_cert is None:
            end_entity_cert = der_bytes
        else:
            intermediates.append(der_bytes)

validator = CertificateValidator(end_entity_cert, intermediates)
try:
    validator = CertificateValidator(end_entity_cert)
    validator.validate_usage(set(['digital_signature']))
except (errors.PathValidationError):
    print("certificate could not be validated")
exit()


with open(certfile, 'rb') as f:
    end_entity_cert = f.read()

cert = OpenSSL.crypto.load_certificate(
      OpenSSL.crypto.FILETYPE_PEM,
      end_entity_cert
)
#validator = CertificateValidator(end_entity_cert)
certByteString = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert)
print (certByteString.decode("utf-8") )

try:
    validator = CertificateValidator(end_entity_cert)
    validator.validate_usage(set(['digital_signature']))
except (errors.PathValidationError):
    print("certificate could not be validated")
    # The certificate could not be validated

exit()
import OpenSSL.crypto
cert = OpenSSL.crypto.load_certificate(
      OpenSSL.crypto.FILETYPE_PEM,
      open(certfile).read()
)

certByteString = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert)
print(type(certByteString))

with open(certfile, 'r') as myfile:
    fileString=myfile.read()#.replace('\n', '')

print("\n\n\n\n\n")
print(fileString)

#print (certByteString.decode("utf-8") )
#print (certByteString)


#exit(0)
nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")
MODEL_NS = "urn:my-urn:my-model"
nsmap_add('pfx', MODEL_NS)
#nsmap_update({'pfx': MODEL_NS})
data = util.elm("bootstrap")

certInfo = util.subelm(data, "certificate-information")
certInfo.append(util.leaf_elm("certificate", fileString))
onboard = util.subelm(data, "onboarding-information")
"""
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
"""
onboard.append(util.leaf_elm("configuration-handling", "append"))
onboard.append(util.leaf_elm("pre-configuration-script", "pre.py"))
onboard.append(util.leaf_elm("configuration", "tbd"))
onboard.append(util.leaf_elm("post-configuration-script", "post.py"))

#print (type(data))
print(etree.tounicode(data, pretty_print=True))
#exit()

session = NetconfSSHSession("172.17.0.3", "8300", "admin", "admin", debug=True)
#reply = session.get_config()
#root, reply, replystring = session.send_rpc("<my-cool-rpc/>")

#root, reply, replystring = session.send_rpc("<bootstrap/>")
root, reply, replystring = session.send_rpc(data)

session.close()

reply_list = list(reply)
for e in reply_list:
    print (e.tag, e.attrib, e.text)
print("\n")
dataElem = reply_list[0]

dataElem = reply.find("nc:data", namespaces=NSMAP)
x = dataElem.find("nc:result", namespaces=NSMAP)
if x is not None:
    print(x.text)
else:
    print("not found")


print("\n")
f = reply.xpath("//nc:data/nc:result", namespaces=NSMAP )
#print(f, type(f))
for ff in f:
    print(ff.text)

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
