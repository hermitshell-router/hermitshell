FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    addgroup -g 1000 hermitshell && \
    adduser -u 1000 -G hermitshell -D hermitshell

COPY hermitshell /usr/local/bin/

EXPOSE 8080 8443

ENV LEPTOS_OUTPUT_NAME="hermitshell"

USER hermitshell

CMD ["hermitshell"]
