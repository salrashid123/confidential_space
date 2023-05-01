package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

var (
	kmsKey      = flag.String("kmsKey", "projects/collaborator-1/locations/global/keyRings/kr1/cryptoKeys/key1", "KMS Key to use")
	audience    = flag.String("audience", "//iam.googleapis.com/projects/248928956783/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier", "Collaborator's audience value")
	user        = flag.String("user", "alice", "user to submit data for")
	host        = flag.String("host", "", "host ip:port to connect to")
	server_name = flag.String("server_name", "tee.operator.com", "SNI of the server")
	ca_files    = flag.String("ca_files", "", "RootCA Chain (PEM)")
	tls_crt     = flag.String("tls_crt", "", "TLS Certificate (PEM)")
	tls_key     = flag.String("tls_key", "", "TLS KEY (PEM)")
)

type PostData struct {
	Key           string `json:"key"`
	Audience      string `json:"audience"`
	EncryptedData string `json:"encrypted_data"`
}

func main() {
	flag.Parse()
	ctx := context.Background()

	caCert, err := ioutil.ReadFile(*ca_files)
	if err != nil {
		fmt.Printf("Error loading ca certificate %v\n", err)
		os.Exit(1)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*tls_crt, *tls_key)
	if err != nil {
		fmt.Printf("Error loading client keypair %v\n", err)
		os.Exit(1)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:   *server_name,
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{cert},
		},
	}
	client := &http.Client{Transport: tr}

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

	e := base64.StdEncoding.EncodeToString(c1_encrypted.Ciphertext)
	p := PostData{
		Key:           *kmsKey,
		Audience:      *audience,
		EncryptedData: e,
	}
	body, err := json.Marshal(p)
	if err != nil {
		fmt.Printf("Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/", *host), "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Result: %s\n", string(htmlData))

}
