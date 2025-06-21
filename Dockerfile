FROM rust:1.87.0-alpine3.22 as builder

RUN apk add --no-cache build-base openssl-dev pkgconfig openssl-libs-static
WORKDIR /app
COPY . .
RUN cargo build --release

FROM alpine:3.22
RUN apk add --no-cache ca-certificates openssl
WORKDIR /app
COPY --from=builder /app/target/release/peerwave /usr/local/bin/
EXPOSE 3000

VOLUME ["/app/config"]
CMD ["peerwave"]
