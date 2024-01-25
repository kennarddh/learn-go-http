FROM golang:1.21 as builder

WORKDIR /app

COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./main.go

FROM scratch

COPY --from=builder /app/main /app/main

EXPOSE 3333

CMD ["/app/main"]