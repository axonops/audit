FROM golang:1.26-alpine AS build
WORKDIR /app
RUN go mod init webhook-receiver
COPY main.go .
RUN CGO_ENABLED=0 go build -o webhook-receiver .

FROM alpine:3.21
COPY --from=build /app/webhook-receiver /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["webhook-receiver"]
