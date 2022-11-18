package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/pubsub"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var (
	topicProject = flag.String("topicProject", "vegas-codelab-5", "ProjectID for the topic to post messages to")
	kmsKey       = flag.String("kmsKey", "projects/collaborator-1/locations/global/keyRings/kr1/cryptoKeys/key1", "KMS Key to use")
	audience     = flag.String("audience", "//iam.googleapis.com/projects/248928956783/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier", "Collaborator's audience value")
	user         = flag.String("user", "alice", "user to submit data for")
)

func main() {
	flag.Parse()

	ctx := context.Background()
	client, err := pubsub.NewClient(ctx, *topicProject)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		fmt.Printf("Error creating KMS client %v\n", err)
		os.Exit(1)
	}

	c1_encrypted, err := kmsClient.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      *kmsKey,
		Plaintext: []byte(*user),
	})
	if err != nil {
		fmt.Printf("Error decoding ciphertext for collaborator %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup

	t := client.Topic("cs-topic")

	result := t.Publish(ctx, &pubsub.Message{
		Attributes: map[string]string{
			"key":      *kmsKey,
			"audience": *audience,
		},
		Data: c1_encrypted.Ciphertext,
	})

	wg.Add(1)
	go func(res *pubsub.PublishResult) {
		defer wg.Done()
		id, err := res.Get(ctx)
		if err != nil {
			fmt.Printf("Failed to publish: %v", err)
			return
		}
		fmt.Printf("Published message msg ID: %v\n", id)
	}(result)

	wg.Wait()

}
