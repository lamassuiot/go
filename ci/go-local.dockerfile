FROM ubuntu:22.04

RUN apt-get update -y && apt-get install -y git ca-certificates gcc libc6-dev libpcsclite-dev

COPY ./bin /usr/local/go-pqc/bin
COPY ./pkg /usr/local/go-pqc/pkg
COPY ./src /usr/local/go-pqc/src
COPY ./lib /usr/local/go-pqc/lib

ENV PATH="/usr/local/go-pqc/bin:$PATH"
ENV GOROOT="/usr/local/go-pqc"
ENV GOPROXY="https://proxy.golang.org,direct"
