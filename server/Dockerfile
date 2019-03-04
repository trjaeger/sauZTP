FROM python:3.6

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y openssh-server openssh-client unzip vim

RUN pip install --upgrade pip

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#COPY ./ ./
#RUN pip install --no-cache-dir -r server/requirements.txt

RUN git clone https://github.com/becarpenter/graspy.git

COPY ./grasp.py ./
RUN cp grasp.py graspy/grasp.py



EXPOSE 22 8300

CMD ["bash"]
#CMD [ "python", "./system-server.py", "--debug" ]
#CMD [ "python", "./system-server.py"]
#CMD [ "python", "./python/grasp_device.py"]
#CMD [ "python", "./tlsClient.py"]

#CMD [ "python", "./python/deviceMain.py"]
