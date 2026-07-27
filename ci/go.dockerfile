#################################################################################################
#                                                                                               #
# Stage 1: bootstrap builder                                                                     #
#                                                                                               #
#################################################################################################

FROM golang:1.26 AS builder

ARG GO_BRANCH=release-branch.go1.27

RUN apt-get update -y && apt-get install -y git

WORKDIR /lamassu-go
RUN git clone -b ${GO_BRANCH} --single-branch --depth 1 https://github.com/lamassuiot/go.git

WORKDIR /lamassu-go/go/src
RUN ./make.bash

#################################################################################################
#                                                                                               #
# Stage 1: Build a clean final image                                                            #
#                                                                                               #
#################################################################################################

FROM ubuntu:22.04

RUN apt-get update -y && apt-get install -y git ca-certificates gcc libc6-dev libpcsclite-dev

COPY --from=builder /lamassu-go/go/bin /usr/local/go-pqc/bin
COPY --from=builder /lamassu-go/go/pkg /usr/local/go-pqc/pkg
COPY --from=builder /lamassu-go/go/src /usr/local/go-pqc/src
COPY --from=builder /lamassu-go/go/lib /usr/local/go-pqc/lib
COPY --from=builder /lamassu-go/go/go.env /usr/local/go-pqc/go.env
COPY --from=builder /lamassu-go/go/VERSION /usr/local/go-pqc/VERSION

ENV PATH "/usr/local/go-pqc/bin:$PATH"
ENV GOROOT="/usr/local/go-pqc"
ENV GOPROXY="https://proxy.golang.org,direct"
