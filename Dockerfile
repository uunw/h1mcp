FROM rust:stable-alpine AS builder
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release 2>/dev/null; rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/target/release/h1mcp /usr/local/bin/h1mcp
ENV H1_USERNAME=""
ENV H1_API_KEY=""
ENTRYPOINT ["/usr/local/bin/h1mcp"]
