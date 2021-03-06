#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI registrar would
provide its contact details to an ANIMA network using GRASP. The
actual BRSKI transactions are not included. Flooding
version, per draft-ietf-anima-bootstrapping-keyinfra-09.
"""

import sys
#sys.path.insert(0, '..') # in case grasp.py is one level up
sys.path.insert(0, 'graspy/')
import grasp
import threading
import time
import socket
try:
    socket.IPPROTO_IPV6
except:
    socket.IPPROTO_IPV6 = 41


###################################
# Utility routine for debugging:
# Print out the GRASP objective registry
# and flood cache
###################################

"""
helper funktion to get your own IP
maybe there is a better way or maybe it should be configured
"""
def findOwnIPv4():
    return socket.gethostbyname(socket.gethostname())

def dump_some():
    grasp.tprint("Objective registry contents:")
    for x in grasp._obj_registry:
        o= x.objective
        grasp.tprint(o.name,"ASA:",x.asa_id,"Listen:",x.listening,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
    grasp.tprint("Flood cache contents:")
    for x in grasp._flood_cache:
        grasp.tprint(x.objective.name,"count:",x.objective.loop_count,"value:",
                     x.objective.value,"source",x.source.locator, x.source.protocol,
                     x.source.port,"expiry",x.source.expire)

####################################
# Thread to flood the objective repeatedly
####################################

class flooder(threading.Thread):
    """Thread to flood objectve repeatedly"""
    def __init__(self, reg_obj, locator, asa_nonce):
        threading.Thread.__init__(self)
        self.running = 1
        self.reg_obj = reg_obj
        self.locator = locator
        self.asa_nonce = asa_nonce

    def stop(self):
        self.running = 0
        grasp.tprint("NOW STOPPING", self.running)

    def run(self):
        while self.running:

            self.reg_obj.value = "EST-TLS"
            grasp.tprint("FLOODING IDENTIFIER: ", self.locator.locator," | IS IPv6: ", self.locator.is_ipaddress)
            #grasp.flood(asa_nonce, 120000,
            #            grasp.tagged_objective(reg_obj,tcp_locator))
            grasp.flood(self.asa_nonce, 120000,
                        grasp.tagged_objective(self.reg_obj,self. locator))
            time.sleep(10)
    #not using          grasp.tagged_objective(reg_obj,udp_locator),
    #not using          grasp.tagged_objective(reg_obj,ipip_locator))

def main(args):
    ###################################
    # Main thread starts here
    ###################################

    grasp.tprint("==========================")
    grasp.tprint("Registrar initializing")
    grasp.tprint("==========================")



    grasp.test_mode = False # set if you want detailed diagnostics
    #time.sleep(1) # time to read the text



    ####################################
    # Register this ASA
    ####################################

    # The ASA name is arbitrary - it just needs to be
    # unique in the GRASP instance. If you wanted to
    # run two registrars in one GRASP instance, they
    # would need different names. For example the name
    # could include a timestamp.
    grasp.skip_dialogue(False,False,True)
    _err, asa_nonce = grasp.register_asa("Reggie")
    #grasp.tprint("TYPE: ", type(asa_nonce))
    #.skip_dialogue(False,False,True)
    if not _err:
        grasp.tprint("ASA Registrar registered OK")
    else:
        grasp.tprint("ASA Registrar failure:",grasp.etext[_err])
        exit() # demo code doesn't handle registration errors
    #grasp.skip_dialogue(False,False,True)

    ####################################
    # Create a TCP port for BRSKI-TCP
    ####################################

    # For this demo, we just make up some numbers:

    tcp_port = 80
    tcp_proto = socket.IPPROTO_TCP
    tcp_address = grasp._my_address # current address determined by GRASP kernel

    ####################################
    # Construct a correponding GRASP ASA locator
    ####################################

    tcp_locator = grasp.asa_locator(tcp_address, None, False)
    tcp_locator.protocol = tcp_proto
    tcp_locator.port = tcp_port
    tcp_locator.is_ipaddress = True

    ####################################
    # Create a IPv4 port for BRSKI-IPv4
    ####################################

    # For this demo, we just make up some numbers:

    ipv4_port = 80
    ipv4_proto = socket.IPPROTO_TCP
    #ipv4_address = '172.2.13.0' #grasp._my_address # current address determined by GRASP kernel
    ipv4_address = findOwnIPv4() # current address determined by GRASP kernel

    ####################################
    # Construct a correponding GRASP ASA locator
    ####################################

    ipv4_locator = grasp.asa_locator(ipv4_address, None, False)
    ipv4_locator.protocol = ipv4_proto
    ipv4_locator.port = ipv4_port
    #ipv4_locator.is_ipaddress = True
    ipv4_locator.is_fqdn = True

    ####################################
    # Construct the GRASP objective
    ####################################

    radius = 255    # Limit the radius of flooding

    reg_obj = grasp.objective("AN_join_registrar")
    reg_obj.loop_count = radius
    reg_obj.synch = True    # needed for flooding
    reg_obj.value = None

    ####################################
    # Register the GRASP objective
    ####################################

    _err = grasp.register_obj(asa_nonce,reg_obj)
    if not _err:
        grasp.tprint("Objective", reg_obj.name, "registered OK")
    else:
        grasp.tprint("Objective registration failure:", grasp.etext[_err])
        exit() # demo code doesn't handle registration errors


    ####################################
    # Start pretty printing
    ####################################

    #grasp.init_bubble_text("BRSKI Join Registrar (flooding method)")
    grasp.tprint("==========================")
    grasp.tprint("Registrar starting now")
    grasp.tprint("==========================")

    ####################################
    # Start flooding thread
    ####################################

    f = flooder(reg_obj, ipv4_locator, asa_nonce)
    f.start()
    #flooder().start()
    grasp.tprint("Flooding", reg_obj.name, "for ever")

    ###################################
    # Listen for requests
    ###################################

    # Here, launch a thread to do the real work of the registrar
    # via the various ports But for the demo, we just pretend...
    #grasp.tprint("Pretending to listen to ports", tcp_port,",", udp_port,
    #             "and for IP-in-IP")


    ###################################
    # Do whatever needs to be done in the main thread
    ###################################

    # At a minimum, the main thread should keep an eye
    # on the other threads and restart them if needed.
    # For the demo, we just dump some diagnostic data...


    try:
        while True:
            time.sleep(5)
            #grasp.tprint("Registrar main loop diagnostic dump:")
            #dump_some()
    except KeyboardInterrupt:
        print('interrupted!')
        grasp.tprint("EXITTING")
        f.stop()
        exit()

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])
