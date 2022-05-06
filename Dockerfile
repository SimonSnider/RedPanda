FROM python:3.8-slim-buster
FROM pandare/panda:latest

RUN apt-get update
RUN apt-get install build-essential -y
RUN apt-get install emacs -y 
RUN pip install pytest
RUN pip install numpy

COPY . .

RUN pip install .