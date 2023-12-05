package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/option"

	kms "cloud.google.com/go/kms/apiv1"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"
	csclaims "github.com/salrashid123/confidential_space/claims"

	"cloud.google.com/go/compute/metadata"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	collaboratorSecrets    arrayFlags
	attestation_token_path = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to Attestation Token file")
	defaultProjectID       = flag.String("project_id", "", "ProjectID for pubsub subscription and logging")
	sleepSec               = flag.Int("sleep", 0, "Just sleep and exit")
)

const (
	jwksURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
)

func main() {
	flag.Var(&collaboratorSecrets, "collaborator", "Formatted collaboratorAudience,kmsKey,ciphertext:  --collaborator=//iam.googleapis.com/projects/[PROJECT_NUMBER]/locations/global/workloadIdentityPools/[POOL_NAME]/providers/[PROVIDER],projects/[PROJECT_NUMBER]/locations/[LOCATION]/keyRings/[KEYRING]/cryptoKeys/[KEY],[ciphertext]")
	flag.Parse()

	// just sleep and exit normally
	if *sleepSec > 0 {
		fmt.Println("Starting Sleep")
		time.Sleep(time.Duration(*sleepSec) * time.Second)
		os.Exit(0)
	}

	if metadata.OnGCE() {
		var err error
		*defaultProjectID, err = metadata.ProjectID()
		if err != nil {
			fmt.Printf("error reading attestation file %v\n", err)
			runtime.Goexit()
		}
	}

	// first verify we're running on confidential_space

	// ***************************************************************************************************

	// print the attestation JSON
	attestation_encoded, err := os.ReadFile(*attestation_token_path)
	if err != nil {
		fmt.Printf("error reading attestation file %v\n", err)
		runtime.Goexit()
	}

	//fmt.Printf("Raw TOKEN (do not do this in real life!  [%s]\n", string(attestation_encoded))
	jwtSet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		fmt.Printf("Unable to load JWK Set: %v", err)
		runtime.Goexit()
	}

	gcpIdentityDoc := &csclaims.Claims{}

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
		runtime.Goexit()
	}

	if claims, ok := token.Claims.(*csclaims.Claims); ok && token.Valid {
		fmt.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Printf(err.Error())
			runtime.Goexit()
		}
		fmt.Printf("%s\n", string(printedClaims))
	} else {
		fmt.Printf("error unmarshalling jwt token %v\n", err)
		runtime.Goexit()
	}

	// now loop through each provider and get their keys
	ctx := context.Background()

	for _, c := range collaboratorSecrets {

		r := strings.Split(c, ",")
		if len(r) != 3 {
			fmt.Printf("     collaborator must be in format:  --collaborator=auidience1,kmsref1,ciphertext1 --collaborator=audience2,kmsref1,ciphertext2")
			runtime.Goexit()
		}
		audienceRef := r[0]
		kmsRef := r[1]
		cipherText := r[2]
		fmt.Printf("bootstrapping  KMS audience [%s] KMSkey [%s] and Secret [%s]\n", audienceRef, kmsRef, cipherText)

		c1_adc := fmt.Sprintf(`{
	"type": "external_account",
	"audience": "%s",
	"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
	"token_url": "https://sts.googleapis.com/v1/token",
	"credential_source": {
	  "file": "%s"
	}
	}`, audienceRef, *attestation_token_path)

		kmsClient, err := kms.NewKeyManagementClient(ctx, option.WithCredentialsJSON([]byte(c1_adc)))
		if err != nil {
			fmt.Printf("Error creating KMS client; skipping message %v\n", err)
			runtime.Goexit()
		} else {
			defer kmsClient.Close()

			b, err := base64.StdEncoding.DecodeString(cipherText)
			if err != nil {
				fmt.Printf("Error decoding ciphertext %v\n", err)
				runtime.Goexit()
			}

			c1_decrypted, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
				Name:       kmsRef,
				Ciphertext: b,
			})
			if err != nil {
				fmt.Printf("Error decoding ciphertext for collaborator %v\n", err)
				runtime.Goexit()
			} else {
				fmt.Println()
				fmt.Printf(">>>>>>>>>>>>> Decrypted Secret %s\n", string(c1_decrypted.Plaintext))
				fmt.Println()
			}
		}
	}

	// now that we have the keypair written to a file, launch applications

	var wg sync.WaitGroup
	wg.Add(2)

	// pretend to run some app, in this case, call itself and just exit
	go func() {
		defer wg.Done()
		fmt.Println("Starting workload 1")
		cmd := exec.Command("/bootstrap", "--sleep=60")

		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, "APP_VERSION=3.4.1")

		var stdBuffer bytes.Buffer
		mw := io.MultiWriter(os.Stdout, &stdBuffer)

		cmd.Stdout = mw
		cmd.Stderr = mw

		if err := cmd.Run(); err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Println(stdBuffer.String())
		fmt.Println("Shutting down workload 1")

	}()

	// pretend to run some other app, in this case, its just sleep for 5mins
	go func() {
		defer wg.Done()
		fmt.Println("Starting workload 2")
		time.Sleep(60 * 5 * time.Second)
		fmt.Println("Shutting down workload 2")
	}()

	wg.Wait()
	fmt.Println("Process completed.")

}

/// ---------------------
