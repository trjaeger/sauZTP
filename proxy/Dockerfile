FROM python:3

WORKDIR /usr/src/app

RUN pip install --upgrade pip

COPY ./ ./
RUN pip install --no-cache-dir -r client/requirements.txt

#COPY requirements.txt ./
#RUN pip install --no-cache-dir -r requirements.txt

RUN apt-get update && apt-get install -y vim

RUN git clone https://github.com/becarpenter/graspy.git

RUN cp grasp.py graspy/grasp.py

#EXPOSE 22
#COPY . .
#CMD [ "bash"]
CMD [ "python", "./python/proxy.py" ]
#CMD [ "python", "./system-server.py" ]
