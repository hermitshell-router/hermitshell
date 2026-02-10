FROM rust:1.75-bookworm AS builder

WORKDIR /app
COPY hermitshell/ ./hermitshell/
COPY Cargo.toml ./

# Build only the hermitshell crate
RUN cargo build --release -p hermitshell

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/hermitshell /usr/local/bin/

EXPOSE 3000

CMD ["hermitshell"]
