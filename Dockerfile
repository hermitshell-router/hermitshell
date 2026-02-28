FROM alpine:latest

ARG S6_OVERLAY_VERSION=3.2.0.2
ARG TARGETARCH
ARG S6_ARCH

# Install s6-overlay (s6 uses x86_64/aarch64, not amd64/arm64)
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && rm /tmp/s6-overlay-noarch.tar.xz
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-${S6_ARCH}.tar.xz && rm /tmp/s6-overlay-${S6_ARCH}.tar.xz

# Runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    nftables \
    iproute2 \
    wireguard-tools \
    conntrack-tools \
    kmod \
    unbound

# Symlinks for Alpine path differences (agent expects Debian paths)
RUN ln -sf /sbin/ip /usr/sbin/ip && \
    ln -sf /sbin/tc /usr/sbin/tc && \
    ln -sf /sbin/modprobe /usr/sbin/modprobe

# Copy binaries (placed by CI or local build script into docker-ctx/{amd64,arm64}/)
COPY docker-ctx/${TARGETARCH}/hermitshell-agent /usr/local/bin/
COPY docker-ctx/${TARGETARCH}/hermitshell-dhcp /usr/local/bin/
COPY docker-ctx/${TARGETARCH}/hermitshell /usr/local/bin/

# s6 service definitions
COPY docker/s6/hermitshell-agent /etc/s6-overlay/s6-rc.d/hermitshell-agent
COPY docker/s6/hermitshell-ui /etc/s6-overlay/s6-rc.d/hermitshell-ui
RUN touch /etc/s6-overlay/s6-rc.d/user/contents.d/hermitshell-agent \
    /etc/s6-overlay/s6-rc.d/user/contents.d/hermitshell-ui

ENV LEPTOS_OUTPUT_NAME="hermitshell"

ENTRYPOINT ["/init"]
