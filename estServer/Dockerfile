FROM debian:latest

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y apt-utils git build-essential libssl1.0-dev
#libssl-dev
RUN git clone https://github.com/cisco/libest.git

WORKDIR /usr/src/app/libest
RUN ./configure && make && make install
WORKDIR /usr/src/app/libest/example/server
RUN echo 1 | ./createCA.sh
#ENTRYPOINT ["openssl"]
CMD [ "bash", "./runserver.sh"]
