# heavily annotated as my dockerlang is bit weak

# get the appropriate go image for the platform as the builder
# docker buildx build --platform linux/amd64,linux/arm64 .
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS builder

# always linux
ARG TARGETOS
# one of amd64 or arm64 based on args above
ARG TARGETARCH

# download deps first, docker does a per line caching so if the prefix matches we reuse
# download deps first before src so any changes to src don't need to download deps agan
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY internal/mediator/ ./internal/mediator/
COPY internal/session/ ./internal/session/
RUN mkdir -p /out /var/lib/token-mediator /etc/token-mediator \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -o /out/token-mediator .

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder --chown=65532:65532 /out/token-mediator /token-mediator
COPY --from=builder --chown=65532:65532 --chmod=0700 /var/lib/token-mediator /var/lib/token-mediator
COPY --from=builder --chown=0:0 --chmod=0755 /etc/token-mediator /etc/token-mediator

USER 65532:65532
ENV CONFIG_PATH=/etc/token-mediator/config.json
ENTRYPOINT ["/token-mediator"]
