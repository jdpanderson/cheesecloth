FROM docker.io/debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive

# The agent is built on the host by 'make e2e' and bind-mounted at /app. It is
# a static binary, so nothing is compiled here: these are the tools the tests
# reach for, and the ones the agent shells out to.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 wireguard-tools \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /

WORKDIR /app

ENTRYPOINT [ "/entrypoint.sh" ]
