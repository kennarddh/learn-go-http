FROM golang:1.21 as builder

WORKDIR /app

COPY . .

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./main.go

FROM scratch

COPY --from=builder /app /bin

EXPOSE 3333

CMD ["/bin/main"]