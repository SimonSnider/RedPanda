FROM python:3.8-slim-buster
FROM pandare/panda:latest
COPY . .
RUN apt-get update
RUN apt-get install build-essential -y
RUN pip install pytest
RUN pip install .