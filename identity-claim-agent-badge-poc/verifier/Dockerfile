# syntax=docker/dockerfile:1

FROM golang:1.27.1-bookworm AS builder

WORKDIR /build/server
ENV CGO_ENABLED=0

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,source=.,target=/build,ro \
    go build -trimpath -o /bin/agntcy-identity-verifier ./cmd/agntcy-identity-verifier

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /bin/agntcy-identity-verifier /agntcy-identity-verifier

USER 65532:65532
ENTRYPOINT ["/agntcy-identity-verifier"]
