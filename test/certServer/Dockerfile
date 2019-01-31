FROM python:3

WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install unzip -y

COPY  files/ca.zip .
RUN unzip *.zip

#COPY python/* .

#CMD ["bash"]
#RUN ls
CMD ["python", "python/certServer.py"]
