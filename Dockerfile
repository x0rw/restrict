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

WORKDIR /home/runner/project

# Install Rust for root (if you want to keep rustup for runner, do it differently)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

RUN /root/.cargo/bin/rustup default stable

ENV PATH="/root/.cargo/bin:${PATH}"

COPY . /home/runner/project
