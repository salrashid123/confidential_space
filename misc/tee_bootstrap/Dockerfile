FROM golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as bootstrap-base
WORKDIR /go/src/app
COPY main.go /go/src/app
COPY go.mod /go/src/app
COPY go.sum /go/src/app
RUN go mod tidy
RUN GOOS=linux GOARCH=amd64 go build -o /go/bin/bootstrap

# base-debian11-root
FROM gcr.io/distroless/base-debian11@sha256:df13a91fd415eb192a75e2ef7eacf3bb5877bb05ce93064b91b83feef5431f37

LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"

COPY --from=bootstrap-base /go/bin/bootstrap /bootstrap

ENTRYPOINT ["/bootstrap"]