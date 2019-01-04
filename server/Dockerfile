FROM python:3

WORKDIR /usr/src/app

#ENV HTTP_PROXY "http://cwproxy.controlware.de:8080"
#ENV HTTPS_PROXY "http://cwproxy.controlware.de:8080"
#ENV http_proxy "http://cwproxy.controlware.de:8080"
#ENV https_proxy "http://cwproxy.controlware.de:8080"

#RUN apt-get update;apt-get install -y wget openssh-server
RUN apt-get update && apt-get install -y openssh-server openssh-client
#RUN mkdir /var/run/sshd
#RUN echo 'root:screencast' | chpasswd
#RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

#ENV NOTVISIBLE "in users profile"
#RUN echo "export VISIBLE=now" >> /etc/profile

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
#EXPOSE 22 80
#COPY ./files ./
#COPY C:\Hochschule\masterarbeit\src\server\files ./
#COPY C:/Hochschule/masterarbeit/src/server/files/ ./
#COPY C:\Hochschule\masterarbeit\src\server\files\system-server.py ./system-server.py
#COPY c:/Hochschule/masterarbeit/src/server/files/ .
#COPY C:/Hochschule/files/ .

EXPOSE 22 8300

#CMD ["bash"]
#RUN service ssh start
#CMD ["service ssh start"]
#CMD [ "python", "./server.py" ]
#CMD [ "python", "./system-server.py", "--debug" ]
CMD [ "python", "./system-server.py"]
