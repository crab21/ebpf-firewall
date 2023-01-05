FROM rust:latest 
WORKDIR /service
COPY . .
COPY ip_white /root/ip_white

RUN rustup toolchain add nightly \
    && rustup component add rust-src --toolchain nightly \
    && cargo install cargo-generate \
    && cargo install bpf-linker \
    && cargo install bindgen-cli

CMD ["cargo", "xtask" ,"run"]

