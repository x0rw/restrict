FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential curl gcc pkg-config libclang-dev clang cmake

# Install Rustup
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /project
