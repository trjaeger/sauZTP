# Provision Server
# YANG

The folder *yang/* also contains the used YANG Module.

# Python
Contains all the code.
### APServer.py

This program is fullfills both the functions of an Registrar and a bootstrap server.
All functions are implemented as different threads launched by this file.
Communications is realised using queues.

## GRASP_RegServer.py
Advertises itself as an registrar using GRASP messages.

### REST_Server.py
Provides the */requestvoucher * URI and handles the voucher requests.
For this purpse it verifyes the signature and authenticates the device using its DevID.
After authentication it provides the device with an ownership voucher.
The signing process of the MASA is simulated.

### NETCONF_client.py
Implements two RPCs: &lt;ownership&gt; and &lt;boostrap&gt;.
&lt;ownership&gt; proofes that tha NETCONF Server is also owned by the legitimate owner of the device and &lt;boostrap&gt; sends the actual bootstrap informations.


### TLS_Server.py
Ignore this file.
Earlier version of the RESTful Server.

# Files
contains files used while developing, will delete soon
