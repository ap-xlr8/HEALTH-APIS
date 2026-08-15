FROM golang:1.25.13 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/healthos ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/healthos /app/healthos
COPY api /app/api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/healthos"]
