FROM golang:1.21 as builder

WORKDIR /app

COPY . .

ENV GOCACHE=/root/.cache/go-build

RUN --mount=type=cache,target="/root/.cache/go-build"  go mod download
RUN --mount=type=cache,target="/root/.cache/go-build" CGO_ENABLED=0 GOOS=linux go build -o main ./main.go

FROM scratch

COPY --from=builder /app/main /app/main

EXPOSE 3333

CMD ["/app/main"]