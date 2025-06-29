FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    gcc \
    pkg-config \
    libclang-dev \
    clang \
    cmake \
    libseccomp-dev \
    sudo \
    ca-certificates \
    qemu-user-static

# Create a non-root user
RUN useradd -ms /bin/bash runner && echo "runner ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Switch to runner user
USER runner
WORKDIR /home/runner/project

# Install Rust for runner user (non-interactive)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/home/runner/.cargo/bin:${PATH}"

COPY --chown=runner:runner . /home/runner/project
