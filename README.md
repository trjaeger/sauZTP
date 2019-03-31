# sauZTP - secure automatic universal zero touch provisioning

This git is a proof of concept for my master theses.
Send me a message if you want to read it (its in German) or see [this short paper](https://github.com/trjaeger/sauZTP/blob/master/sauZTP_shortPaper.pdf).


## Abstract

    The networking industry is lacking a secure and truly universal zero touch protocol for network devices.
    Proprietary solutions based on mechanisms like DHCP exist, but do not offer the desired functionality, especially with regard to security.
    As each manufacturer develops a solution for its own ecosystem, the solutions are not compatible with each other.

    This paper presents a solution for this problem, using the management protocol NETCONF to transmit bootstrapping informations.
    To ensure security its based on mutual authentication, based on 802.1AR DevID certificates.
    Trust between the device ad the bootstrapping infrastructure is achieved by an ownership voucher.
    This is a cryptographic artifact signed by the manufacturer to assure that the bootstrapping server belongs to the legitimate owner of a device.


## Overview

After completing its boot sequence the pledge waits for an *GRASP M_Flood* Message of either an proxy or the registrar.
Then it sends an REST Call to the */requestvoucher* URI and authenticates itself with its DevID.
After verifying and authenticating this certificate the Server answers this with an [ownership voucher](https://tools.ietf.org/html/draft-ietf-anima-voucher-06) signed by the *Manufacturer Authorized Signing Authority (MASA)*.
Because the pledge has an implicit trust with the MASA it can now verify if the server belongs to is its legitimate owner.

This procedure guarantees mutual authentication and the actual provisioning process can begin.
For that the pledge opens a NETCONF Server and waits for incoming remote procedure calls.
The first remote procedure call is again an proof of ownership, because in reality registrar and bootstrap server might not be the same device.
After that the server sends the actual bootstrap RPC is send which contains the following YANG Module.
The Module contains all information, the device needs to get in a state ready for production.

### Bootstrap RPC YANG module tree view
For simplicity and due the lack of standardized modules, most values are defined as strings, although in the future more specific types for e.g. the hash algorithm will be suitable.

    module: bootstrap-information
    +--rw bootstrap-information
       +--rw id                      string
       +--rw boot-image
       |  +--rw name                 string
       |  +--rw version              string
       |  +--rw download-uri         string
       |  +--rw verification
       |     +--rw hash-algorithm?   string
       |     +--rw hash-value?       string
       +--rw configuration-handling? string
       +--rw pre-configuration-script
       |  +--rw filename             string
       |  +--rw interpreter          string
       |  +--rw download-uri         string
       |  +--rw verification
       |     +--rw hash-algorithm?   string
       |     +--rw hash-value?       string
       +--rw configuration?          binary
       +--rw post-configuration-script
          +--rw filename             string
          +--rw interpreter          string
          +--rw download-uri         string
          +--rw verification
             +--rw hash-algorithm?   string
             +--rw hash-value?       string


## Docker Containers:
The commands are mostly for documentation purposes, use your own paths accordingly.
Also create a IPv6 network and connect the containers to it.
The volumes are just needed for development, I will fix this later.

### pledge - simulates a device connecting to the network for the first time

    docker build -t pledge .
    docker run -it -P --rm --name running-client --network="my_ipv6_bridge" -v ~/src/client/python:/usr/src/app/python pledge

### server - provision server and Registrar
Can be two different machines, but for simplicity this container does both roles

    docker build -t server .
    ddocker run -it -P --rm --name running-server -v ~/src/server/files/:/usr/src/app/ server

### EST-Server
A dockerized version of ciscos [LibEst](https://github.com/cisco/libest).
Currently not in use, but will be used to provide the pledge with a domain certificate after authentication.

### test/
contains additional containers used for testing purposes. Ignore them I will delete them soon.

# Acknowledgment and License

For license information see [LICENSE.md](https://github.com/trjaeger/sauZTP/blob/master/LICENSE.md).
Basically do with it what you want, but I would highly appreciate it if you let me know if you do something cool with it.

Also I would like to thank the following people for their code:
#### GRASP Code

Based on the experimental implementation of Brian E Carpenter.
See https://github.com/becarpenter/graspy for more information.

#### NETCONF Code

Based on the work of Christian Hopps.
See https://github.com/choppsv1/netconf.
