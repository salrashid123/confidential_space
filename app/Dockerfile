FROM golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN go vet -v
RUN go test -v

RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/server

FROM gcr.io/distroless/base@sha256:75f63d4edd703030d4312dc7528a349ca34d48bec7bd754652b2d47e5a0b7873

LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.log_redirect"="always"

COPY --from=build /go/bin/server /
COPY --from=build /go/src/app/config.json /config.json

COPY --from=build /go/src/app/certs/root-ca-operator.crt /root-ca-operator.crt
COPY --from=build /go/src/app/certs/tee-operator.crt /tee-operator.crt
COPY --from=build /go/src/app/certs/tee-operator.key /tee-operator.key

COPY --from=build /go/src/app/certs/root-ca-collaborator1.crt /root-ca-collaborator1.crt
COPY --from=build /go/src/app/certs/tee-collaborator1.crt /tee-collaborator1.crt
COPY --from=build /go/src/app/certs/tee-collaborator1.key /tee-collaborator1.key

COPY --from=build /go/src/app/certs/root-ca-collaborator2.crt /root-ca-collaborator2.crt
COPY --from=build /go/src/app/certs/tee-collaborator2.crt /tee-collaborator2.crt
COPY --from=build /go/src/app/certs/tee-collaborator2.key /tee-collaborator2.key

EXPOSE 8081

ENTRYPOINT ["/server"]

CMD []
