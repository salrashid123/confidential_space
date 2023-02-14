FROM golang:1.19 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN go vet -v
RUN go test -v

RUN CGO_ENABLED=0 go build -o /go/bin/server

FROM gcr.io/distroless/base@sha256:75f63d4edd703030d4312dc7528a349ca34d48bec7bd754652b2d47e5a0b7873

LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.log_redirect"="always"

COPY --from=build /go/bin/server /
COPY --from=build /go/src/app/config.json /config.json

EXPOSE 8081

ENTRYPOINT ["/server"]

CMD []
