FROM python:3.8-slim-buster
FROM pandare/panda:latest

RUN apt-get update \
  && apt-get install -y python3-pip python3-dev \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip
RUN apt-get install build-essential -y
RUN apt-get install emacs -y 
RUN pip install pytest
RUN pip install numpy

COPY . .
RUN pip install .
