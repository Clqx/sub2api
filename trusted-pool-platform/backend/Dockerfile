FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/trusted-pool-backend ./cmd/server

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/trusted-pool-backend /trusted-pool-backend
USER 65532:65532
EXPOSE 8092
ENTRYPOINT ["/trusted-pool-backend"]
