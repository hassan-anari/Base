FROM rust:1.90-bookworm AS build
WORKDIR /src
COPY . .
ARG BINARY=wallet-mpc-coordinator
RUN cargo build --locked --release --bin "$BINARY" && cp "target/release/$BINARY" /service
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 mpc
COPY --from=build /service /service
USER 10001
ENTRYPOINT ["/service"]
