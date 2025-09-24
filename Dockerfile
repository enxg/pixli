FROM golang:1.25-alpine
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY main.go ./
COPY static/ ./static/
COPY templates/ ./templates/

RUN CGO_ENABLED=0 GOOS=linux go build -o pixli .

EXPOSE 3000

CMD ["/app/pixli"]
