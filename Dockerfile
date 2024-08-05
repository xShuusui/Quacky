FROM python:3.12

RUN apt update && \
    apt install --yes git build-essential autoconf automake libtool intltool cmake sudo curl unzip flex bison && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

COPY requirements.txt .

RUN pip install -r requirements.txt

RUN git clone --recursive https://github.com/vlab-cs-ucsb/ABC.git

WORKDIR /tmp/ABC/build

RUN python install-build-deps.py && \
    rm -rf /tmp/*

WORKDIR /usr/src
