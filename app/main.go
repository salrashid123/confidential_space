package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/pubsub"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat/go-jwx/jwk"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var (
	config                 = flag.String("config", "config.json", "Arbitrary config file")
	attestation_token_path = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to Attestation Token file")
	serverShutdownTime     = flag.Int64("server_shutdown_time", 30, "shutdown TEE in mins")

	// map to hold all the users currently found and the number of times
	// they've been sent
	users = map[string]int32{}
)

const (
	subscription = "cs-subscribe" // the subscription where both collaborators submit messages; you could also setup 1 topic/subscription for each collaborator as well
	jwksURL      = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
)

func main() {

	flag.Parse()

	c1_cred, err := os.ReadFile(*config)
	if err != nil {
		fmt.Println("error reading  config file")
		os.Exit(1)
	}

	config := map[string]string{}

	err = json.Unmarshal(c1_cred, &config)
	if err != nil {
		fmt.Println("error parsing config file")
		os.Exit(1)
	}

	fmt.Printf("Config file %v\n", config)

	// print the attestation JSON

	attestation_encoded, err := os.ReadFile(*attestation_token_path)
	if err != nil {
		fmt.Println("error reading attestation file")
		os.Exit(1)
	}

	//fmt.Printf("Raw TOKEN (do not do this in real life!  [%s]\n", string(attestation_encoded))
	jwtSet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		fmt.Printf("Unable to load JWK Set: %v", err)
		os.Exit(1)
	}

	gcpIdentityDoc := &Claims{}

	token, err := jwt.ParseWithClaims(string(attestation_encoded), gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}
		if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
			return key[0].Materialize()
		}
		return nil, errors.New("unable to find key")
	})
	if err != nil {
		fmt.Printf("     Error parsing JWT %v", err)
		os.Exit(1)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		fmt.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Printf(err.Error())
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(printedClaims))
	} else {
		fmt.Printf("error unmarshalling jwt token %v\n", err)
		return
	}

	//  Start listening to pubsub messages

	ctx := context.Background()

	// try to derive the projectID from the default metadata server creds
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		fmt.Printf("Error finding default credentials %v\n", err)
		os.Exit(1)
	}

	if creds.ProjectID == "" {
		fmt.Printf("error finding default projectID \n")
		return
	}

	fmt.Printf("Using projectID for subscription: %s\n", creds.ProjectID)

	client, err := pubsub.NewClient(ctx, creds.ProjectID)
	if err != nil {
		fmt.Printf("Error creating pubsub client %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Printf("Beginning subscription: %s\n", subscription)

	sub := client.Subscription(subscription)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(*serverShutdownTime)*time.Minute)
	defer cancel()

	var received int32
	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		fmt.Printf("Got MessageID ID: %s\n", msg.ID)
		received++
		key, keyok := msg.Attributes["key"]
		audience, audienceok := msg.Attributes["audience"]

		if keyok && audienceok {
			// bootstrap Collaborator credentials;  decrypt with KMS key
			// note, we're creating a new kmsclient on demand based on what is sent in the message alone.
			// realistically, the KMS audience and key would be using configuration values and not simply use what is sent in the message
			fmt.Printf("bootstrapping  KMS key [%s] for collaborator [%s]\n", key, audience)
			c1_adc := fmt.Sprintf(`{
		"type": "external_account",
		"audience": "%s",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url": "https://sts.googleapis.com/v1/token",
		"credential_source": {
		  "file": "%s"
		}
		}`, audience, *attestation_token_path)
			kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsJSON([]byte(c1_adc)))
			if err != nil {
				fmt.Printf("Error creating KMS client; skipping message %v\n", err)
			} else {
				c1_decrypted, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
					Name:       key,
					Ciphertext: msg.Data,
				})
				if err != nil {
					fmt.Printf("Error decoding ciphertext for collaborator %v\n", err)
				} else {
					currentUser := string(c1_decrypted.Plaintext)
					c, ok := users[currentUser]
					if ok {
						users[currentUser] = atomic.AddInt32(&c, 1)
						fmt.Printf(">>>>>>>>>>> Found user [%s] count  %d\n", currentUser, c)
					} else {
						users[currentUser] = 1
						fmt.Printf(">>>>>>>>>>> User %s not found, adding to list", currentUser)
					}
				}
			}
		} else {
			fmt.Printf("key or audience attribute not sent; skipping message processing\n")
		}
		msg.Ack()
	})
	if err != nil {
		fmt.Printf("Error reading pubsub subscription %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Shutting down server after reading %d messages\n", received)

}
