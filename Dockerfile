FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO_ENABLED=0 produces a static binary that runs in a minimal alpine image.
RUN CGO_ENABLED=0 go build -o pot-node .

FROM alpine:3.21
COPY --from=builder /src/pot-node /usr/local/bin/pot-node
ENTRYPOINT ["pot-node"]
