package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"log"

	"cloud.google.com/go/compute/metadata"
	kms "cloud.google.com/go/kms/apiv1"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/genproto/googleapis/api/monitoredres"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/pubsub"
	"github.com/golang-jwt/jwt"
	"github.com/lestrrat/go-jwx/jwk"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var (
	config                 = flag.String("config", "config.json", "Arbitrary config file")
	attestation_token_path = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to Attestation Token file")
	project_id             = flag.String("project_id", "", "ProjectID for pubsub subscription and logging")
	serverShutdownTime     = flag.Int64("server_shutdown_time", 30, "shutdown TEE in mins")

	// map to hold all the users currently found and the number of times
	// they've been sent
	users = map[string]int32{}
)

const (
	subscription = "cs-subscribe" // the subscription where both collaborators submit messages; you could also setup 1 topic/subscription for each collaborator as well
	jwksURL      = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	logName      = "cs-log"
)

func main() {

	flag.Parse()

	ctx := context.Background()

	// configure a logger client
	logger := log.Default()

	// try to derive the projectID from the default metadata server creds
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		logger.Fatalf("Error finding default credentials %v\n", err)
	}

	// derive the projectID to send logs and pubsub subscribe.  If specified in command line, use that.  Otherwise derive from creds
	if *project_id == "" {
		if creds.ProjectID == "" {
			logger.Fatalf("error: --project_id parameter is null and unable to get projectID from credentials\n")
		}
		*project_id = creds.ProjectID
	}

	// if we're running on GCE Conf-space, use the cloud logging api instead of stdout/stderr
	if metadata.OnGCE() {
		logClient, err := logging.NewClient(ctx, *project_id)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}
		defer logClient.Close()

		// derive the projectID, instanceID and zone
		//  these three are used to 'label' the log lines back to the specific gce_instance logs
		p, err := metadata.ProjectID()
		if err != nil {
			log.Fatalf("Failed to get projectID from metadata server: %v", err)
		}
		i, err := metadata.InstanceID()
		if err != nil {
			log.Fatalf("Failed to get instanceID from metadata server: %v", err)
		}
		z, err := metadata.Zone()
		if err != nil {
			log.Fatalf("Failed to get zone from metadata server: %v", err)
		}

		m := make(map[string]string)
		m["project_id"] = p
		m["instance_id"] = i
		m["zone"] = z
		logger = logClient.Logger(logName, logging.CommonResource(
			&monitoredres.MonitoredResource{
				Type:   "gce_instance",
				Labels: m,
			},
		)).StandardLogger(logging.Info)
	}

	c1_cred, err := os.ReadFile(*config)
	if err != nil {
		logger.Printf("error reading  config file %v\n", err)
		runtime.Goexit()
	}

	config := map[string]string{}

	err = json.Unmarshal(c1_cred, &config)
	if err != nil {
		logger.Printf("error parsing config file %v\n", err)
		runtime.Goexit()
	}

	logger.Printf("Config file %v\n", config)

	// print the attestation JSON

	attestation_encoded, err := os.ReadFile(*attestation_token_path)
	if err != nil {
		logger.Printf("error reading attestation file %v\n", err)
		runtime.Goexit()
	}

	//logger.Printf("Raw TOKEN (do not do this in real life!  [%s]\n", string(attestation_encoded))
	jwtSet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		logger.Printf("Unable to load JWK Set: %v", err)
		runtime.Goexit()
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
		logger.Printf("     Error parsing JWT %v", err)
		runtime.Goexit()
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		logger.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			logger.Printf(err.Error())
			runtime.Goexit()
		}
		logger.Printf("%s\n", string(printedClaims))
	} else {
		logger.Printf("error unmarshalling jwt token %v\n", err)
		return
	}

	//  Start listening to pubsub messages
	client, err := pubsub.NewClient(ctx, *project_id)
	if err != nil {
		logger.Printf("Error creating pubsub client %v\n", err)
		runtime.Goexit()
	}
	defer client.Close()

	logger.Printf("Beginning subscription: %s\n", subscription)

	sub := client.Subscription(subscription)

	ctx, cancel := context.WithTimeout(ctx, time.Duration(*serverShutdownTime)*time.Minute)
	defer cancel()

	var received int32
	err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
		logger.Printf("Got MessageID ID: %s\n", msg.ID)
		received++
		key, keyok := msg.Attributes["key"]
		audience, audienceok := msg.Attributes["audience"]

		if keyok && audienceok {
			// bootstrap Collaborator credentials;  decrypt with KMS key
			// note, we're creating a new kmsclient on demand based on what is sent in the message alone.
			// realistically, the KMS audience and key would be using configuration values and not simply use what is sent in the message
			logger.Printf("bootstrapping  KMS key [%s] for collaborator [%s]\n", key, audience)
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
				logger.Printf("Error creating KMS client; skipping message %v\n", err)
			} else {
				c1_decrypted, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
					Name:       key,
					Ciphertext: msg.Data,
				})
				if err != nil {
					logger.Printf("Error decoding ciphertext for collaborator %v\n", err)
				} else {
					currentUser := string(c1_decrypted.Plaintext)
					c, ok := users[currentUser]
					if ok {
						users[currentUser] = atomic.AddInt32(&c, 1)
						logger.Printf(">>>>>>>>>>> Found user [%s] count  %d\n", currentUser, c)
					} else {
						users[currentUser] = 1
						logger.Printf(">>>>>>>>>>> User %s not found, adding to list", currentUser)
					}
				}
			}
		} else {
			logger.Printf("key or audience attribute not sent; skipping message processing\n")
		}
		msg.Ack()
	})
	if err != nil {
		logger.Printf("Error reading pubsub subscription %v\n", err)
		runtime.Goexit()
	}
	logger.Printf("Shutting down server after reading %d messages\n", received)
}
