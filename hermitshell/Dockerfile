FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY hermitshell /usr/local/bin/

EXPOSE 80 443

ENV LEPTOS_OUTPUT_NAME="hermitshell"
CMD ["hermitshell"]
