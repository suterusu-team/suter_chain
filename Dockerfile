FROM parity/rust-builder as builder
ARG PROFILE=release
COPY . /builds
WORKDIR /builds/node
RUN cargo build --$PROFILE --all

FROM phusion/baseimage:0.11
ARG PROFILE=release
COPY --from=builder /builds/node/target/$PROFILE/suter-node /usr/local/bin
EXPOSE 30333 9933 9944
VOLUME ["/data"]
WORKDIR /data
CMD ["suter-node", "--dev", "--ws-external"]
