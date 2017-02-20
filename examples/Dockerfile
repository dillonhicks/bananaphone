# Do you even paranoia?
FROM python:3.6

LABEL maintainer.email "chronodynamic@gmail.com"
LABEL dockerfile.version "2017.02.20"
LABEL description "Example using volatile-memory-only ssh identities in docker build"

ARG CREDENTIALS_PORT

COPY . /app
WORKDIR /app

RUN export CREDENTIALS_PORT=$CREDENTIALS_PORT; \
    pip install git+https://github.com/dillonhicks/bananaphone.git#egg && \
    exec-with-identity pip install -r requirements.txt && \
    exec-with-identity git clone --branch master --depth 1 git@github.com:dillonhicks/bananaphone.git

CMD ['bash']
