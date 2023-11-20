FROM golang:1.21.4-alpine

ENV APP_NAME cutcutfilm
ENV APP_SERVICE_NAME cutcutfilm-user
ENV APP_HOME /app/${APP_NAME}/services/user
WORKDIR "$APP_HOME"

RUN apk add --no-cache git

ARG GIT_USER
ARG GIT_TOKEN

RUN git config --global url."https://${GIT_USER}:${GIT_TOKEN}@github.com".insteadOf "https://github.com"

ENV GO111MODULE=on
ENV GOPRIVATE=github.com/${GIT_USER}/*
ENV CGO_ENABLED=0

COPY . .

RUN go mod tidy
RUN go build -v -o "$APP_SERVICE_NAME"

RUN chmod +x ./$APP_SERVICE_NAME
CMD ["sh", "-c", "./$APP_SERVICE_NAME"]