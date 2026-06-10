FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        openssh-client \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /src/target/release/TermiteRS /usr/local/bin/termiters

ENV GIT_SSH_COMMAND="ssh -o StrictHostKeyChecking=accept-new"

ENTRYPOINT ["termiters"]
