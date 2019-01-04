FROM ubuntu:16.04
#FROM python:2
WORKDIR /opt/
RUN apt-get update && apt-get install -y git nodejs npm python-setuptools libpcre3-dev
#RUN apt-get update && apt-get install -y git nodejs npm python-setuptools libpcre3-dev

RUN easy_install pip
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN git clone https://github.com/freenetconf/yang-creator.git
RUN cd /opt/yang-creator && ln -sf /usr/bin/nodejs /usr/bin/node
RUN export PYTHON=python2
RUN cd /opt/yang-creator && npm install

EXPOSE 8888

CMD [ "bash"]
#CMD [ "./opt/yang-creator/server.js"]
