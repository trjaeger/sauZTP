relevant Docker Containers:

client - simulates device 
    docker build -t server .
    docker run -it -P --rm --name running-server -v ~/src/server/files/:/usr/src/app/ server
    
server - provision server
    docker build -t client .
    docker run -it -P --rm --name running-client -v ~/src/client/python:/usr/src/app/python client
