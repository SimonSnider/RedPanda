FROM python:latest
FROM pandare/panda:latest
COPY . .
RUN apt-get install build-essential -y
RUN pip install pytest
RUN pip install .
