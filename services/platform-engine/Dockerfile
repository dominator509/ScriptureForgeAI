# Build from the repository root so the production cmd/platform-engine package
# and shared internal packages are included in the image.
FROM golang:1.24.3-bookworm AS build

ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/scriptureforge-api ./cmd/platform-engine

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/scriptureforge-api /usr/local/bin/scriptureforge-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/scriptureforge-api"]
