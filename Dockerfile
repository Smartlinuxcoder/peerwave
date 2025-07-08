FROM rust:1.87.0-alpine3.22 AS chef
RUN apk add --no-cache build-base openssl-dev pkgconfig openssl-libs-static

RUN cargo install cargo-chef
WORKDIR /app

FROM oven/bun:alpine AS bun
COPY . .
RUN bun install
RUN bunx tailwindcss -i ./tailwind.css -o ./assets/tailwind.css

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM alpine:3.22 AS dioxus_cli_prep
RUN apk add --no-cache curl unzip
WORKDIR /dioxus
RUN curl -L \
    https://github.com/DioxusLabs/dioxus/archive/refs/tags/v0.7.0-alpha.2.zip \
  -o dioxus.zip \
 && unzip dioxus.zip \
 && mv dioxus-* ./src
WORKDIR /dioxus/src

FROM rust:1.87.0-alpine3.22 AS dioxus_cli_buildmaxxer
RUN apk add --no-cache build-base openssl-dev pkgconfig openssl-libs-static
COPY --from=dioxus_cli_prep /dioxus/src /dioxus/src
WORKDIR /dioxus/src
RUN cargo install --path packages/cli --root /usr/local

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
COPY --from=bun /home/bun/app/assets/tailwind.css ./assets/tailwind.css
COPY --from=dioxus_cli_buildmaxxer /usr/local /usr/local

ENV PATH="/usr/local/bin:$PATH"

RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN dx bundle -r --platform web

FROM chef AS runtime
COPY --from=builder /app/target/dx/peerwave/release/web/ /usr/local/app

ENV PORT=8080
ENV IP=0.0.0.0

EXPOSE 8080

WORKDIR /usr/local/app
ENTRYPOINT [ "/usr/local/app/peerwave" ]