FROM golang:1.21 as builder

WORKDIR /src

COPY . .

RUN go build

FROM scratch

COPY --from=builder /src/main /src/main

CMD ["/src/main"]