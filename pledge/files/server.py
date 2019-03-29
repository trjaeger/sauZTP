from netconf import nsmap_update, server
import netconf.util as ncutil
import sys
import time
from lxml import etree

MODEL_NS = "urn:my-urn:my-model"
nsmap_update({'pfx': MODEL_NS})

class MyServer (object):
    def __init__ (self, user, pw):
        controller = server.SSHUserPassController(username=user, password=pw)
        self.server = server.NetconfSSHServer(server_ctl=controller, server_methods=self, port=8300, debug=1)

    def nc_append_capabilities(self, caps):
        #ncutil.subelm(caps, "capability").text = MODEL_NS
        return

    def rpc_my_cool_rpc (self, session, rpc, *params):
        data = ncutil.elm("nc:data")
        #data = ncutil.elm("data")
        #data.append(ncutil.leaf_elm("pfx:result", "RPC result string"))
        data.append(ncutil.leaf_elm("result", "RPC result string"))
        #print (type(data), data.tag, data.attrib)
        print(etree.tounicode(rpc))
        print(session, params)
        return data

    def rpc_bootstrap(self, unused, rpc, *params):
        print (rpc.text)
        return ncutil.elm("ok")
# ...
server = MyServer("admin", "admin")
# ...
if sys.stdout.isatty():
    print("^C to quit server")
try:
    while True:
        time.sleep(1)
except Exception as e:
    print (e)
    print("quitting server")

#server.close()


print("End")
