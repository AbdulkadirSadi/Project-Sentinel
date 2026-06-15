# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder
WORKDIR /app

RUN apk add --no-cache git

# Bağımlılıkları önce indir (cache dostu)
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-w -s' -o sentinel-server .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=builder /app/sentinel-server .

# Sertifikalar volume olarak bağlanır (docker-compose.yml)
VOLUME ["/app/certs"]

EXPOSE 8080 8081
CMD ["./sentinel-server"]
