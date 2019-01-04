FROM python:3

WORKDIR /usr/src/app

#ENV HTTP_PROXY "http://cwproxy.controlware.de:8080"
#ENV HTTPS_PROXY "http://cwproxy.controlware.de:8080"
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#RUN apt-get update && apt-get install -y openssh-server


EXPOSE 22
#COPY . .
#CMD [ "bash"]
CMD [ "python", "./client.py" ]
#CMD [ "python", "./system-server.py" ]
