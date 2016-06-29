FROM debian:jessie

WORKDIR /root/
RUN apt-get update
RUN apt-get install -y \
    python-dev \
    python-pip

RUN pip install pyinstaller==3.1.1

ADD filterapi /root/src/filterapi
RUN cd /root/src/ && pyinstaller --onefile filterapi
