#client for netconf
from netconf.client import NetconfSSHSession
from lxml import etree
import netconf.util as util
from netconf import nsmap_add, nsmap_update
from netconf import NSMAP

import re

nsmap_add("sys", "urn:ietf:params:xml:ns:yang:ietf-system")
MODEL_NS = "urn:my-urn:my-model"
nsmap_add('pfx', MODEL_NS)
#nsmap_update({'pfx': MODEL_NS})
data = util.elm("bootstrap")
redirect = util.subelm(data, "redirect-information")
boots_server = util.subelm(redirect, "bootstrap-server")
boots_server.append(util.leaf_elm("address", "172.17.0.1"))
boots_server.append(util.leaf_elm("port", "8300"))
boots_server.append(util.leaf_elm("trust_anchor", "undefined"))

onboard = util.subelm(data, "onboarding-information")
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

#print (type(data))
print(etree.tounicode(data, pretty_print=True))
exit()

session = NetconfSSHSession("172.17.0.2", "8300", "admin", "admin", debug=True)
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
