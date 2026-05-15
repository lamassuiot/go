#################################################################################################
#                                                                                               #
# Stage 1: bootsrap builder                                                                     #
#                                                                                               #
#################################################################################################

FROM golang:1.26 AS builder

RUN apt-get update -y && apt-get install git

WORKDIR /
RUN git clone -b direct-fork https://github.com/lamassuiot/pqc-cloudflare-go.git

WORKDIR /pqc-cloudflare-go/src
RUN ./make.bash

#################################################################################################
#                                                                                               #
# Stage 1: Build a clean final image                                                            #
#                                                                                               #
#################################################################################################

FROM ubuntu:22.04

COPY --from=builder /pqc-cloudflare-go/bin /usr/local/go-pqc/bin
COPY --from=builder /pqc-cloudflare-go/pkg /usr/local/go-pqc/pkg
COPY --from=builder /pqc-cloudflare-go/src /usr/local/go-pqc/src
COPY --from=builder /pqc-cloudflare-go/lib /usr/local/go-pqc/lib

ENV PATH "/usr/local/go-pqc/bin:$PATH"
ENV GOROOT="/usr/local/go-pqc"
