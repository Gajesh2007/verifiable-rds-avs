FROM rust:1.78-slim as builder

WORKDIR /usr/src
COPY core ./core
COPY verification/Cargo.toml verification/Cargo.lock ./verification/
COPY verification/src ./verification/src

WORKDIR /usr/src/verification

# Create a dummy main.rs to cache dependencies
RUN mkdir -p ./src && \
    echo "fn main() {}" > ./src/main.rs && \
    cargo build --release && \
    rm -f ./src/main.rs

# Build the actual code
RUN cargo build --release

FROM debian:12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /usr/src/verification/target/release/verifiable-db-verification /app/

EXPOSE 8080

ENV PG_HOST=postgres
ENV PG_PORT=5432
ENV PG_USER=verifiable
ENV PG_PASSWORD=verifiable
ENV PG_DATABASE=verifiable_db
ENV API_PORT=8080

CMD ["/app/verifiable-db-verification"] 