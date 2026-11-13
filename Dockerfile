# syntax=docker/dockerfile:1
# ---- build ----
# Static musl binary: the runtime image then needs no libc, libgcc or OpenSSL.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && \
    install -D -m 0555 target/release/clamv-webui /out/clamv-webui && \
    install -d -m 0700 /out/data

# ---- runtime: no shell, no package manager, no shared libraries ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=0:0 /out/clamv-webui /app/clamv-webui
# Same UID/GID as the Java image, so existing volumes keep working.
COPY --from=build --chown=10001:10001 /out/data /app/data
VOLUME ["/app/data"]
USER 10001:10001
ENV LISTEN_ADDR=0.0.0.0:8080 DATA_DIR=/app/data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/clamv-webui", "healthcheck"]
ENTRYPOINT ["/app/clamv-webui"]
CMD ["serve"]
