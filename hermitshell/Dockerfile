FROM rust:latest AS builder

WORKDIR /app
COPY Cargo.toml ./
COPY hermitshell/ ./hermitshell/
COPY hermitshell-agent/ ./hermitshell-agent/
COPY hermitshell-common/ ./hermitshell-common/
COPY hermitshell-dhcp/ ./hermitshell-dhcp/
COPY hermitshell-ui/ ./hermitshell-ui/

# Build only the hermitshell crate
RUN cargo build --release -p hermitshell

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/hermitshell /usr/local/bin/

EXPOSE 3000

CMD ["hermitshell"]
