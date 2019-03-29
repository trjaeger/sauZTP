from netconf import nsmap_update, server
import netconf.util as ncutil

MODEL_NS = "urn:my-urn:my-model"
nsmap_update({'pfx': MODEL_NS})

class MyServer (object):
    def __init__ (self, user, pw):
        controller = server.SSHUserPassController(username=user, password=pw)
        self.server = server.NetconfSSHServer(server_ctl=controller, server_methods=self)

    def nc_append_capabilities(self, caps):
        ncutil.subelm(caps, "capability").text = MODEL_NS

    def rpc_my_cool_rpc (self, session, rpc, *params):
        data = ncutil.elm("data")
        data.append(ncutil.leaf_elm("pfx:result", "RPC result string"))
        return data

# ...
server = MyServer("myuser", "mysecert")
# ...
if sys.stdout.isatty():
    print("^C to quit server")
try:
    while True:
        time.sleep(1)
except Exception:
    print("quitting server")

s.close()


print("End")
