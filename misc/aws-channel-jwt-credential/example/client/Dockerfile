# go1.19.8 linux/amd64
FROM docker.io/golang@sha256:9f2dd04486e84eec72d945b077d568976981d9afed8b4e2aeb08f7ab739292b3 as build

WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -buildvcs=false  -o /go/bin/client

RUN chown root:root /go/bin/client && \
  chown -R root:root /go/src/app

# for go-credential
FROM gcr.io/distroless/base-debian11@sha256:df13a91fd415eb192a75e2ef7eacf3bb5877bb05ce93064b91b83feef5431f37

# for process credential
#FROM debian:latest

LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.log_redirect"="always"
RUN apt-get update && apt-get install libc6 ca-certificates -y
WORKDIR /
COPY --from=build /go/bin/client  /client
COPY --from=build /go/src/app/certs /certs
COPY --from=build /go/src/app/aws-channel-jwt-process-credential  /aws-channel-jwt-process-credential
COPY --from=build /go/src/app/config  /root/.aws/config
ENV AWS_SDK_LOAD_CONFIG=1

ENTRYPOINT ["/client"]
CMD []
