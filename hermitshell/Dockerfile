FROM alpine:latest

RUN apk add --no-cache ca-certificates libcap && \
    addgroup -g 1000 hermitshell && \
    adduser -u 1000 -G hermitshell -D hermitshell

COPY hermitshell /usr/local/bin/

RUN setcap cap_net_bind_service=+ep /usr/local/bin/hermitshell

EXPOSE 80 443

ENV LEPTOS_OUTPUT_NAME="hermitshell"

USER hermitshell

CMD ["hermitshell"]
