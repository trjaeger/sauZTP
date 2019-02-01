# Docker Containers:
the commands are mostly for documentation purposes, use your own paths accordingly

## client - simulates device 

    docker build -t server .
    docker run -it -P --rm --name running-client -v ~/src/client/python:/usr/src/app/python client
    
## server - provision server

    docker build -t client .
    ddocker run -it -P --rm --name running-server -v ~/src/server/files/:/usr/src/app/ server
        
## proxy - implementation of the registration proxy
    docker build -t proxy .
    docker run -it -P --rm --name running-proxy -v ~/src/proxy/python:/usr/src/app/python proxy
    
## test/ - contains additional containers used for testing purposes 
