package main

import (
	"flag"
	"fmt"
	"log"

	ek "github.com/salrashid123/confidential_space/misc/aws-channel-jwt-credential/credential"

	"github.com/aws/aws-sdk-go/aws"

	//"github.com/aws/aws-sdk-go/aws/credentials/processcreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

const ()

var (
	region = flag.String("region", "us-east-2", "Region")
	bucket = flag.String("bucket", "mineral-minutia", "Bucket")
	//command = flag.String("command", "/aws-channel-jwt-process-credential   --host=localhost:8081 --endpoint=https://server.domain.com:8081/token --audience=https://server.domain.com --sts-sni=server.domain.com --trust-ca=/path/to/certs/certs/tls-ca-chain.pem --use-mtls=true   --cert=/path/to/certs/client-svc.crt --key=/path/to/certs/client-svc.key", "Command to run")
	//command = flag.String("command", "/aws-channel-jwt-process-credential   --host=localhost:8081 --endpoint=https://server.domain.com:8081/token --audience=https://server.domain.com --sts-sni=server.domain.com --trust-ca=/certs/tls-ca-chain.pem --use-mtls=true   --cert=/certs/client-svc.crt --key=/certs/client-svc.key  --aws-arn=\"arn:aws:iam::291738886548:role/gcpsts\"  --aws-session-name=mysession   --use-assume-role=true", "Command to run")
)

func main() {

	flag.Parse()

	// for process creds
	//creds := processcreds.NewCredentials(*command)
	creds, err := ek.NewEKMAWSCredentials(ek.CredConfig{
		STSEndpointHost: "localhost:8081",
		STSEndpoint:     "https://server.domain.com:8081/token",
		STSSNI:          "server.domain.com",
		Audience:        "https://server.domain.com",
		UseMTLS:         true,
		TrustCA:         "certs/tls-ca-chain.pem",
		ClientCert:      "certs/client-svc.crt",
		ClientKey:       "certs/client-svc.key",
		AWSRoleArn:      "arn:aws:iam::291738886548:role/gcpsts", // Required if UseAssumeRole=true
		AWSSessionName:  "foo",                                   // used if UseAssumeRole=true, if unset a random sessionname is selected by the server
		UseAssumeRole:   true,                                    // if false, then a SessionToken is issued
		Duration:        900,
	})
	if err != nil {
		log.Fatalf("Error creating session:  %v", err)
	}
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(*region),
		Credentials: &creds,
	},
	)
	if err != nil {
		log.Fatalf("Error creating session:  %v", err)
	}
	svcs := s3.New(sess)

	sresp, err := svcs.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(*bucket)})
	if err != nil {
		log.Fatalf("Error listing objects:  %v", err)
	}

	for _, item := range sresp.Contents {
		fmt.Printf("Object  %s\n", *item.Key)
	}

}
