# Pledge
Simulates a device completing boot sequence and waiting for bootstrap.

# Python
Contains all the code and lots of file snot used anymore.
Also contains some of the certificates used for several functions.
I will clean this up soon.
## deviceMain.py
The main program of the device.
All functions are implemented as different threads launched by this file.
Communications is realized using queues.

## GRASP_device.py
Waits for incoming messages of containing a proxy or registrar advertisement.
Signals the address back to the main program.

## REST_client.py
Takes the address from the GRASP service and sends out a voucher request.
Also waits for the request containing the voucher.

TODO: Stores the voucher in a trusted devices database.

## NETCONF_server.py

Implements the endpoints for the &lt;ownership&gt; and &lt;boostrap&gt; RPCs.

## est-test.py and TLS_client.py

Earlier versions used for testing. Ignore these files. Will delete them soon.

# Files
contains files used while developing, will delete soon
