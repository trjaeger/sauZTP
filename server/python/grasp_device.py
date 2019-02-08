#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""This is some demo code showing how a BRSKI pledge would
find a proxy in an ANIMA network using GRASP. This version
assumes the proxy advertises itself to on-link pledge nodes
seeking a proxy by flooding. The actual BRSKI transactions are
not included.
"""

import sys
#sys.path.insert(0, '..') # assumes grasp.py is one level up
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
# Map protocols to method names
###################################
pm={socket.IPPROTO_UDP: "UDP",
    socket.IPPROTO_TCP: "TCP",
    socket.IPPROTO_IPV6: "IPIP"}

###################################
# Utility routine for debugging:
# Print out the GRASP objective registry
# and flood cache
###################################

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

###################################
# Main thread starts here
###################################


grasp.tprint("==========================")
grasp.tprint("ASA Pledji is starting up.")
grasp.tprint("==========================")
grasp.tprint("Pledji is a demonstration Autonomic Service Agent.")
grasp.tprint("It mimics a BRSKI Pledge (joining node) by")
grasp.tprint("looking for a Join Assistant (proxy) and the")
grasp.tprint("methods it supports. Then it pretends to")
grasp.tprint("generate BRSKI traffic.")
grasp.tprint("This version corresponds to")
grasp.tprint("draft-ietf-anima-bootstrapping-keyinfra-12")
#grasp.tprint('modulo an error in the "AN_proxy" definition')
grasp.tprint("On Windows or Linux, there should soon be")
grasp.tprint("a nice window that displays the process.")
grasp.tprint("==========================")

#grasp.test_mode = True # tell everybody it's a test, will print extra diagnostics
time.sleep(1) # time to read the text


####################################
# Register this ASA
####################################

# The ASA name is arbitrary - it just needs to be
# unique in the GRASP instance.

grasp.skip_dialogue(False,False,True)
_err,_asa_nonce = grasp.register_asa("Pledji")
if not _err:
    grasp.tprint("ASA Pledji registered OK")
else:
    grasp.tprint("ASA registration failure:",grasp.etext[_err])
    exit()

####################################
# Construct a GRASP objective
####################################

# This is an empty GRASP objective to find the proxy
# It's only used for get_flood so doesn't need to be filled in

proxy_obj = grasp.objective("AN_proxy")
proxy_obj.synch = True

reg_obj = grasp.objective("AN_join_registrar")
reg_obj.synch = True


#grasp.init_bubble_text("BRSKI Pledge (flooding method)")
grasp.tprint("Pledge starting now")

###################################
# Now find the proxy(s) and registrationserver(s)
###################################

while True:
    proxy = None
    registrar1 = None

    _err, _results = grasp.get_flood(_asa_nonce, proxy_obj)
    if not _err:
        # _results contains all the unexpired tagged objectives
        grasp.tprint("Found",len(_results),"result(s)")
        for x in _results:
            # Extract the details
            try:
                x.method = pm[x.source.protocol]
            except:
                x.method = "Unknown"
            # Print the result
            grasp.tprint("\n\n",x.objective.name, "flooded from", x.source.locator, x.source.protocol,
                        x.source.port,"expiry",x.source.expire,
                        "method", x.method, "\n\n")

            # use whatever logic you want to decide which proxy to use.
            # For the demo code, we randomize somewhat:
            #if grasp._prng.randint(0,1):
            proxy = x

    else:
        grasp.tprint("get_flood from proxy failed", grasp.etext[_err])

    _err, _results = grasp.get_flood(_asa_nonce, reg_obj)
    if not _err:
        # _results contains the returned locators if any
        for x in _results:
            grasp.tprint("Got", reg_obj.name, "at",
                         x.source.locator, x.source.protocol, x.source.port)
                         #"Got AN_join_registrar at None 6 7017"
            grasp.tprint("\n\nGot", reg_obj.name, "at",  x.source.locator, x.source.protocol, x.source.port, "\n\n")
            #Got AN_join_registrar at 2002:ac14::3 6 80

            registrar1 = x.source

        #grasp.tprint(registrar1, registrar2)
        #<grasp.asa_locator object at 0x7fd37cc16390> None
    else:
        grasp.tprint("get_flood ffrom registrar failed", grasp.etext[_err])

    if registrar1:
        grasp.tprint("\n\ncan contact registrar directly at ", registrar1.locator, "\n")
    elif proxy:
        grasp.tprint("\n\will contact registrar directly with proxy ", proxy.locator, "\n")
    else:
        grasp.tprint("\n\ncan not contact anyone\n")

    '''
    if proxy:
        p_addr = proxy.source.locator
        p_proto = proxy.source.protocol
        p_port = proxy.source.port
        p_method = proxy.method
        grasp.tprint("Chose proxy: address", p_addr, "protocol", p_proto,
                     "port", p_port, "method", p_method)

        ###################################
        # Connect to the proxy
        ###################################

        # Here, do the socket calls etc. to talk
        # to the proxy.
        # But for the demo, we just pretend...

        try:
            grasp.tprint("Pretending to contact proxy")
            # (socket calls etc)
            # simulate a random failure with a divide-by-zero
            _= 1/grasp._prng.randint(0,3)

        except:
            # Socket failure, tag this proxy as expired.
            # (Since floods expire, eventually the bad proxy
            # will vanish anyway, but this call avoids the wait.)
            grasp.tprint("Communication failed, expiring that proxy")
            grasp.expire_flood(_asa_nonce, proxy)

        ###################################
        # Wait and loop back to find another proxy
        ###################################
'''
    time.sleep(5) # wait chosen to avoid synchronicity with Procksy
