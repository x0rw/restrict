FROM rust:slim-bookworm AS builder

RUN apt-get update && apt-get install -y \
    clang \
    cmake \
    libclang-dev \
    libseccomp-dev \
    pkg-config \
    qemu-user-static \
    sudo \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash runner && echo "runner ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Use non-root user
USER runner
WORKDIR /home/runner/project

COPY --chown=runner . .

