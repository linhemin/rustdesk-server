FROM ubuntu:24.04
ARG BUILD_VERSION
ARG SOURCE_DIGEST
LABEL org.opencontainers.image.version=$BUILD_VERSION \
      org.rustdesk.server.source-digest=$SOURCE_DIGEST
COPY hbbs hbbr /usr/local/bin/
COPY libsodium.so.23 /usr/lib/x86_64-linux-gnu/libsodium.so.23
COPY libsodium-copyright /usr/share/doc/libsodium23/copyright
WORKDIR /root
