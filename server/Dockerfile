FROM python:3.6

WORKDIR /usr/src/app

RUN pip install --upgrade pip


COPY ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#COPY ./ ./
#RUN pip install --no-cache-dir -r client/requirements.txt

#RUN apt-get update && apt-get install -y apt-utils

#RUN apt-get update && apt-get install -y openssh-server
RUN git clone https://github.com/becarpenter/graspy.git

COPY ./grasp.py ./
RUN cp ./grasp.py graspy/grasp.py
EXPOSE 22
#COPY . .

CMD [ "bash"]

#CMD [ "python", "./python/RegServer.py" ]
#CMD [ "python", "./python/tlsServer.py" ]

#CMD [ "python", "./client.py" ]
#CMD [ "python", "./system-server.py" ]
