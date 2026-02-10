FROM golang:1.24-bookworm AS builder

WORKDIR /src

RUN apt-get update && apt-get install -y ca-certificates

COPY ./clients/fw/go.mod ./clients/fw/go.sum ./clients/fw/
COPY ./clients/wg/go.mod ./clients/wg/go.sum ./clients/wg/
COPY ./clients/supervisor/go.mod ./clients/supervisor/go.sum ./clients/supervisor/
COPY ./submodules/headscale/go.mod ./submodules/headscale/go.sum ./submodules/headscale/
COPY ./utils/go.mod ./utils/go.sum ./utils/
COPY ./clients/ipdrawer/go.mod ./clients/ipdrawer/go.sum ./clients/ipdrawer/
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /out/log-collector ./cmd/log-collector

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

ENV PORT=8080
ENV DATA_DIR=/data

WORKDIR /app
COPY --from=builder /out/log-collector /app/log-collector

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/app/log-collector"]
