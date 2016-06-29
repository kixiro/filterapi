FROM centos:6


WORKDIR /root/
RUN yum install -y \
    wget \
    xz \
    gcc \
    curl \
    libxml2-devel \
    libxslt-devel \
    libpcap-devel \
    zlib-dev \
    openssl-devel \
    sqlite-devel \
    bzip2-devel \
    make
RUN wget https://www.python.org/ftp/python/2.7.11/Python-2.7.11.tar.xz
RUN xz -d Python-2.7.11.tar.xz
RUN tar xvf Python-2.7.11.tar
RUN cd Python-2.7.11 && \
    ./configure --enable-shared --prefix=/usr/local && \
    make && \
    make altinstall

RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && \
    curl https://bootstrap.pypa.io/get-pip.py | /usr/local/bin/python2.7 -

RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && \
    /usr/local/bin/pip install pyinstaller==3.1.1

ADD filterapi /root/src/filterapi
RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib && \
    cd /root/src/ && \
    pyinstaller --onefile filterapi
