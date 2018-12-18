FROM python:3

WORKDIR /usr/src/app

ENV HTTP_PROXY "http://cwproxy.controlware.de:8080"
ENV HTTPS_PROXY "http://cwproxy.controlware.de:8080"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#COPY . .

#CMD [ "python", "./server.py" ]
CMD [ "python", "./system-server.py" ]
