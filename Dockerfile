FROM rust:1.78.0 AS builder

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get install -y libseccomp-dev --no-install-recommends && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /usr/src/app

# COPY --from=builder /usr/src/app/target/release/restrict ./

CMD ["cargo", "test"]
