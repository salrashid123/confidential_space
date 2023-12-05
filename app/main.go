package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"log"

	"cloud.google.com/go/compute/metadata"
	kms "cloud.google.com/go/kms/apiv1"
	csclaims "github.com/salrashid123/confidential_space/claims"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/genproto/googleapis/api/monitoredres"

	// confidentialcomputingpb "cloud.google.com/go/confidentialcomputing/apiv1/confidentialcomputingpb"

	"cloud.google.com/go/logging"
	"cloud.google.com/go/pubsub"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	config                        = flag.String("config", "config.json", "Arbitrary config file")
	attestation_token_path        = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to Attestation Token file")
	custom_attestation_token_path = flag.String("custom_attestation_token_path", "/run/container_launcher/teeserver.sock", "Path to Custom Attestation socket")
	project_id                    = flag.String("project_id", "", "ProjectID for pubsub subscription and logging")

	// for mtls certificates
	default_ca      = flag.String("default_ca", "certs/root-ca-operator.crt", "Operator RootCA Chain (PEM)")
	default_tls_crt = flag.String("default_tls_crt", "certs/tee-operator.crt", "Operator TLS Certificate (PEM)")
	default_tls_key = flag.String("default_tls_key", "certs/tee-operator.key", "Operator TLS KEY (PEM)")

	// collaborator mtls certs and keys materialized within the TEE
	collaborator1_ca      = flag.String("collaborator1_ca", "certs/root-ca-collaborator1.crt", "Collaborator 1 RootCA Chain (PEM)")
	collaborator1_tls_crt = flag.String("collaborator1_tls_crt", "certs/tee-collaborator1.crt", "Collaborator 1 TLS Certificate (PEM)")
	collaborator1_tls_key = flag.String("collaborator1_tls_key", "certs/tee-collaborator1.key", "Collaborator 1 TLS KEY (PEM)")

	collaborator2_ca      = flag.String("collaborator2_ca", "certs/root-ca-collaborator2.crt", "Collaborator 2 RootCA Chain (PEM)")
	collaborator2_tls_crt = flag.String("collaborator2_tls_crt", "certs/tee-collaborator2.crt", "Collaborator 2 TLS Certificate (PEM)")
	collaborator2_tls_key = flag.String("collaborator2_tls_key", "certs/tee-collaborator2.key", "Collaborator 2 TLS KEY (PEM)")

	marshal_custom_token_string_as_array = flag.Bool("marshal_custom_token_string_as_array", false, "Try to parse audience and eat_token as string array even if single string")

	// map to hold all the users currently found and the number of times
	// they've been sent
	users       = map[string]int32{}
	instance_id string

	logger *log.Logger
	mu     sync.Mutex
)

const (
	subscription = "cs-subscribe" // the subscription where both collaborators submit messages; you could also setup 1 topic/subscription for each collaborator as well
	jwksURL      = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	logName      = "cs-log"
)

type connectRequest struct {
	Uid string `json:"uid"`
}

type connectResponse struct {
	Uid            string `json:"uid"`
	AttestationJWT string `json:"attestation_jwt"`
}

type getSigningCertRequest struct {
	CN string `json:"cn"`
}

type getSigningCertResponse struct {
	Certificate    string `json:"certificate"`
	AttestationJWT string `json:"attestation_jwt"`
	SignedData     string `json:"signed_data"`
	Signature      string `json:"signature"`
}

type incrementRequest struct {
	Key           string `json:"key"`
	Audience      string `json:"audience"`
	EncryptedData string `json:"encrypted_data"`
}

type incrementResponse struct {
	User  string `json:"user"`
	Count int32  `json:"count"`
}

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
)

type customToken struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

// contextKey is used to pass http middleware certificate details
type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
	EKM              string
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Userip is not host:port", http.StatusBadGateway)
			return
		}
		userIP := net.ParseIP(ip)
		if userIP == nil {
			http.Error(w, "error parsing remote IP", http.StatusBadGateway)
			return
		}
		logger.Printf("Request client IP: %s\n", ip)

		// cert verification was already done during tls.Config.GetConfigForClient earlier
		//   where we only allow client certs and cas from the collaborators specifically.
		//   this is just a recheck
		if len(r.TLS.VerifiedChains) == 0 {
			logger.Printf("Unverified client certificate from: %s\n", ip)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// for gcp healthchecks if we allow mtls bypass only for /healthz endpoint
		// if r.URL.Path == "/healthz" {
		// 	// https://cloud.google.com/load-balancing/docs/l7-internal#firewall_rules
		// 	lbSubnetA := "35.191.0.0/16"
		// 	lbSubnetB := "130.211.0.0/22"
		// 	_, ipnetA, err := net.ParseCIDR(lbSubnetA)
		// 	if err != nil {
		// 		logger.Printf("Error checking remote IP Subnet: %s\n", ip)
		// 		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// 		return
		// 	}
		// 	_, ipnetB, err := net.ParseCIDR(lbSubnetB)
		// 	if err != nil {
		// 		logger.Printf("Error checking remote IP Subnet: %s\n", ip)
		// 		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// 		return
		// 	}
		// 	c1 := net.ParseIP(ip)

		// 	if !(ipnetA.Contains(c1) || ipnetB.Contains(c1)) {
		// 		logger.Printf("Error Healthcheck request not from LB Subnet: %s\n", ip)
		// 		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// 		return
		// 	}
		// } else if len(r.TLS.VerifiedChains) == 0 {
		// 	logger.Printf("Error: only /healthz endpoint is allowed without client certificates: %s\n", ip)
		// 	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		// 	return
		// }

		ekm, err := r.TLS.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logger.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

		event := &event{
			PeerCertificates: r.TLS.PeerCertificates,
			EKM:              hex.EncodeToString(ekm),
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func healthhandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func incrementCounter(ctx context.Context, audience, key string, data []byte) (string, int32, error) {
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
		return "", 0, err
	} else {
		c1_decrypted, err := kmsClient.Decrypt(ctx, &kmspb.DecryptRequest{
			Name:       key,
			Ciphertext: []byte(data),
		})
		if err != nil {
			logger.Printf("Error decoding ciphertext for collaborator %v\n", err)
			return "", 0, err
		} else {
			currentUser := string(c1_decrypted.Plaintext)
			mu.Lock()
			defer mu.Unlock()
			users[currentUser] = users[currentUser] + 1
			return currentUser, users[currentUser], nil
		}
	}
}

// establish a TLS connection with the TEE
//
//	the response back to the client will contain the EKM value encoded in the eat_nonce
//	the audience value just happens to be the client certificates hash
//	  (yes, the aud: bit with client cert this isn't at all useful, i was just looking for a reason to use aud field)
func connectHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	var clientCertHash string
	// note val.PeerCertificates[0] is the leaf
	for _, c := range val.PeerCertificates {
		h := sha256.New()
		h.Write(c.Raw)
		clientCertHash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	logger.Println("Got Connect request")

	var post connectRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		logger.Printf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	customTokenValue, err := getCustomAttestation(customToken{
		Audience:  clientCertHash,
		Nonces:    []string{val.EKM, clientCertHash},
		TokenType: TOKEN_TYPE_OIDC,
	})
	if err != nil {
		logger.Printf("     Error creating Custom JWT %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&connectResponse{
		Uid:            post.Uid,
		AttestationJWT: customTokenValue,
	})
}

// generate an RSA key inside the TEE and return a self signed cert
// encode the public key's fingerprint as the eat_nonce value so the client knows
// it was generated here
func certHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	var clientCertHash string
	for _, c := range val.PeerCertificates {
		h := sha256.New()
		h.Write(c.Raw)
		clientCertHash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	var post getSigningCertRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		logger.Printf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	logger.Printf("Got POST Data  %v\n", post)

	// generate an rsa key and certificate inside this instance
	instanceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Printf("Error generating rsa key %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pub := instanceKey.Public()
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	logger.Printf("generated Public Key \n%s\n", string(pubPEM))

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 1)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		logger.Printf("Error creating cert serial number %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// either issue a self-singed local x509 bound to this key (as shown below)
	// or generate a csr and get a cert issued from any remote CA
	//   for example gcp private CA: https://gist.github.com/salrashid123/f06eacd80a25611a7c322d8e6f99942f#gcp-private-ca
	//                               https://github.com/salrashid123/tls_ak/blob/main/server/grpc_attestor.go#L534-L619
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         post.CN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  []string{instance_id},
		KeyUsage:  x509.KeyUsageDigitalSignature,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	instanceCertificateDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, instanceKey)
	if err != nil {
		logger.Printf("Error creating cert %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: instanceCertificateDER,
		},
	)
	logger.Printf("Instance Certificate: \n%s\n", certPEM)
	instanceCertificate, err := x509.ParseCertificate(instanceCertificateDER)
	if err != nil {
		logger.Printf("Error creating cert  %v\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// calculate the certificate hash and place that into an eat_nonce value
	hasher := sha256.New()
	hasher.Write(instanceCertificate.Raw)
	instanceCertificateHash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	logger.Printf("instance Certificate Hash %s\n", instanceCertificateHash)

	customTokenValue, err := getCustomAttestation(customToken{
		Audience:  clientCertHash,
		Nonces:    []string{instanceCertificateHash},
		TokenType: TOKEN_TYPE_OIDC,
	})
	if err != nil {
		logger.Printf("     Error creating Custom JWT %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// create a test signature which the client can verify
	dataToSign := "foo"
	th := sha256.New()
	th.Write([]byte(dataToSign))
	signature, err := rsa.SignPKCS1v15(nil, instanceKey, crypto.SHA256, th.Sum(nil))
	if err != nil {
		logger.Printf("     Error from signing: %s\n", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&getSigningCertResponse{
		AttestationJWT: customTokenValue,
		Certificate:    base64.StdEncoding.EncodeToString(instanceCertificate.Raw),
		SignedData:     dataToSign,
		Signature:      base64.StdEncoding.EncodeToString(signature),
	})
}

// just increment the counter
func incrementHandler(w http.ResponseWriter, r *http.Request) {
	// val := r.Context().Value(contextKey("event")).(event)

	var post incrementRequest
	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		logger.Printf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	logger.Printf("Got POST Data  %v\n", post)

	if post.Audience == "" || post.Key == "" {
		logger.Printf("Error: post data must include an audience and key")
		http.Error(w, "post data must include an audience and key", http.StatusBadRequest)
		return
	}
	b, err := base64.StdEncoding.DecodeString(post.EncryptedData)
	if err != nil {
		logger.Printf("Error b64 decoding POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, c, err := incrementCounter(r.Context(), post.Audience, post.Key, b)
	if err != nil {
		logger.Printf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&incrementResponse{
		User:  u,
		Count: c,
	})
}

func getCustomAttestation(tokenRequest customToken) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", *custom_attestation_token_path)
			},
		},
	}

	customJSON, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", err
	}

	logger.Printf("Posting Custom Token %s\n", string(customJSON))

	url := "http://localhost/v1/token"
	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(customJSON)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errorResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("Error creating custom token %s", string(errorResponse))
	}
	tokenBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(tokenBytes), nil
}

func main() {

	flag.Parse()

	ctx := context.Background()

	// configure a logger client
	log.SetOutput(os.Stdout)
	log.SetOutput(os.Stderr)
	logger = log.Default()

	// try to derive the projectID from the default metadata server creds
	creds, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		logger.Printf("Error finding default credentials %v\n", err)
		os.Exit(1)
	}

	// derive the projectID to send logs and pubsub subscribe.  If specified in command line, use that.  Otherwise derive from creds
	if *project_id == "" {
		if creds.ProjectID == "" {
			logger.Printf("error: --project_id parameter is null and unable to get projectID from credentials\n")
			os.Exit(1)
		}
		*project_id = creds.ProjectID
	}

	// if we're running on GCE Conf-space, use the cloud logging api instead of stdout/stderr
	// and read in instance variables

	if metadata.OnGCE() {
		logClient, err := logging.NewClient(ctx, *project_id)
		if err != nil {
			logger.Printf("Failed to create client: %v", err)
			os.Exit(1)
		}
		defer logClient.Close()

		// derive the projectID, instanceID and zone
		//  these three are used to 'label' the log lines back to the specific gce_instance logs.
		//  use runtime.Goexit() from after setup to flush any deferred cloud logging log entries before exiting
		p, err := metadata.ProjectID()
		if err != nil {
			logger.Printf("Failed to get projectID from metadata server: %v", err)
			os.Exit(1)
		}
		instance_id, err = metadata.InstanceID()
		if err != nil {
			logger.Printf("Failed to get instanceID from metadata server: %v", err)
			os.Exit(1)
		}
		z, err := metadata.Zone()
		if err != nil {
			logger.Printf("Failed to get zone from metadata server: %v", err)
			os.Exit(1)
		}

		m := make(map[string]string)
		m["project_id"] = p
		m["instance_id"] = instance_id
		m["zone"] = z
		logger = logClient.Logger(logName, logging.CommonResource(
			&monitoredres.MonitoredResource{
				Type:   "gce_instance",
				Labels: m,
			},
		)).StandardLogger(logging.Info)
	}

	// load a sample config file, this isn't really used at the moment
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

	logger.Printf("Loaded sample config file %v\n", config)

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
	}, jwt.WithLeeway(1*time.Second))
	if err != nil {
		logger.Printf("     Error parsing JWT %v", err)
		runtime.Goexit()
	}

	if claims, ok := token.Claims.(*csclaims.Claims); ok && token.Valid {
		logger.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			logger.Printf(err.Error())
			runtime.Goexit()
		}
		logger.Printf("%s\n", string(printedClaims))
	} else {
		logger.Printf("error unmarshalling jwt token %v\n", err)
		runtime.Goexit()
	}

	// create a custom token with an EKM value which we will send to httpbin
	//  ofcourse httpbin cannot verify the EKM and JWT; this is just to demonstrate the flow

	// first create a TLS connection since we need the EKM value
	conn, err := tls.Dial("tcp", "httpbin.org:443", &tls.Config{})
	if err != nil {
		logger.Printf("Error connecting to remote server %v\n", err)
		runtime.Goexit()
	}
	cs := conn.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		logger.Printf("Error extracting ekm %v\n", err)
		runtime.Goexit()
	}
	logger.Printf("EKM my_nonce: %s\n", hex.EncodeToString(ekm))

	// now issue the custom JWT with the EKM value and any other random string; note eat_nonce needs to be of a minimum size (i think 16bytes?)
	customTokenValue, err := getCustomAttestation(customToken{
		Audience:  "https://httpbin.org",
		Nonces:    []string{hex.EncodeToString(ekm), "0000000000000000001"},
		TokenType: TOKEN_TYPE_OIDC,
	})
	if err != nil {
		logger.Printf("     Error creating Custom JWT %v", err)
		runtime.Goexit()
	}

	jwt.MarshalSingleStringAsArray = *marshal_custom_token_string_as_array

	// parse it back (this isn't ofcourse necessary, this just shows what a remote server should do with the bearer token)
	customtokenParsed, err := jwt.ParseWithClaims(customTokenValue, gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}
		if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
			return key[0].Materialize()
		}
		return nil, errors.New("unable to find key")
	}, jwt.WithLeeway(1*time.Second))
	if err != nil {
		logger.Printf("     Error parsing JWT %v", err)
		runtime.Goexit()
	}

	if claims, ok := customtokenParsed.Claims.(*csclaims.Claims); ok && token.Valid {
		logger.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			logger.Printf(err.Error())
		}
		logger.Printf(">>>>>>>>>>  Custom JWT %s\n", string(printedClaims))
	} else {
		logger.Printf("error unmarshalling jwt token %v\n", err)
		runtime.Goexit()
	}

	// now that we have the custom JWT, we can send the JWT as a bearer token to the remote site and print the results.
	//  since w'ere sending it to httpbin, the results will be an echo of the headers we sent to it

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := http.Client{
		Transport: tr,
	}

	req, err := http.NewRequest(http.MethodGet, "https://httpbin.org/get", nil)
	if err != nil {
		logger.Printf("error creating a request to remote server %v\n", err)
		runtime.Goexit()
	}

	// do something here with the ekm value before the request is sent but after the connection is setup...
	//   like create a jwt with the ekm as claim, send it as a bearer header token..
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", customTokenValue))
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("error submitting request to httpbin %v\n", err)
		runtime.Goexit()
	}

	htmlData, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("error reading response body %v\n", err)
		runtime.Goexit()
	}
	defer resp.Body.Close()
	logger.Printf("Status from httpbin: %s\n", resp.Status)
	logger.Printf("Response from httpbin %s\n", string(htmlData))

	//  Start listening to pubsub messages on background
	pubsubClient, err := pubsub.NewClient(ctx, *project_id)
	if err != nil {
		logger.Printf("Error creating pubsub client %v\n", err)
		runtime.Goexit()
	}
	defer pubsubClient.Close()

	logger.Printf("Beginning subscription: %s\n", subscription)
	quit := make(chan bool)
	sub := pubsubClient.Subscription(subscription)
	go func(ctx context.Context) {
		for {
			select {
			case <-quit:
				return
			default:
				err = sub.Receive(ctx, func(_ context.Context, msg *pubsub.Message) {
					logger.Printf("Got MessageID ID: %s\n", msg.ID)
					key, keyok := msg.Attributes["key"]
					audience, audienceok := msg.Attributes["audience"]
					if keyok && audienceok {
						u, c, err := incrementCounter(ctx, audience, key, msg.Data)
						if err != nil {
							logger.Printf("error incrementing counter: %v\n", err)
						} else {
							logger.Printf(">>>>>>>>>>> Found user [%s] count  %d\n", u, c)
						}
					} else {
						logger.Printf("key or audience attribute not sent; skipping message processing\n")
					}
					msg.Ack()
				})
				if err != nil {
					logger.Printf("Error reading pubsub subscription %v\n", err)
					return
				}
			}
		}
	}(ctx)

	// start http server on main
	router := mux.NewRouter()
	router.Methods(http.MethodPost).Path("/connect").HandlerFunc(connectHandler)
	router.Methods(http.MethodPost).Path("/cert").HandlerFunc(certHandler)
	router.Methods(http.MethodPost).Path("/increment").HandlerFunc(incrementHandler)
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthhandler)

	// load default server certs
	default_server_certs, err := tls.LoadX509KeyPair(*default_tls_crt, *default_tls_key)
	if err != nil {
		logger.Printf("Error loading default certificates %v\n", err)
		quit <- true
		runtime.Goexit()
	}

	// load the CA client cert and server certificates
	// load rootCA for CA_1
	client1_root, err := os.ReadFile(*collaborator1_ca)
	if err != nil {
		logger.Printf("Error loading collaborator1 ca certificate %v\n", err)
		quit <- true
		runtime.Goexit()
	}

	client1_root_pool := x509.NewCertPool()
	client1_root_pool.AppendCertsFromPEM(client1_root)

	// load rootCA for CA_2
	client2_root, err := os.ReadFile(*collaborator2_ca)
	if err != nil {
		logger.Printf("Error loading collaborator2 ca certificate %v\n", err)
		quit <- true
		runtime.Goexit()
	}

	client2_root_pool := x509.NewCertPool()
	client2_root_pool.AppendCertsFromPEM(client2_root)

	// load the server certs issued by both ca1 and ca2, pretend these should use get loaded
	// from each collaborators's secret manager or private ca using the attestation token (similar to the KMS decryption)
	server1_cert, err := tls.LoadX509KeyPair(*collaborator1_tls_crt, *collaborator1_tls_key)
	if err != nil {
		logger.Printf("Error loading collaborator1 server certificates %v\n", err)
		quit <- true
		runtime.Goexit()
	}

	server2_cert, err := tls.LoadX509KeyPair(*collaborator2_tls_crt, *collaborator2_tls_key)
	if err != nil {
		logger.Printf("Error loading collaborator2 server certificates %v\n", err)
		quit <- true
		runtime.Goexit()
	}

	// *****************************************

	// set TLS configs based on the SNI of the requestor.
	// the following sets custom TLS enforcements where both client and server cert enforcement is controlled
	// by each collaborator (i.,e a client for collaborator can set client and server certs for their own use)
	// basically, if the certificates are materialized by each collaborator using workload federation, then each
	// client that connects _to_ the TEE using mTLS must be authorized by each individual collaborator by issuing them client certificates
	//   the only SNI that does not require client certs is the /healthz healthcheck path which is checked within eventsMiddleware().  That capability is current commented out
	tlsConfig := &tls.Config{
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{default_server_certs}, // have to specify something here though its not used
		MinVersion:   tls.VersionTLS13,
		GetConfigForClient: func(ci *tls.ClientHelloInfo) (*tls.Config, error) {
			if ci.ServerName == "tee.collaborator1.com" {
				return &tls.Config{
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS13,
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  client1_root_pool,
					GetCertificate: func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return &server1_cert, nil
					},
				}, nil
			}
			if ci.ServerName == "tee.collaborator2.com" {
				return &tls.Config{
					NextProtos: []string{"h2", "http/1.1"},
					MinVersion: tls.VersionTLS13,
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  client2_root_pool,
					GetCertificate: func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return &server2_cert, nil
					},
				}, nil
			}

			// if you want to handle a bypass for healthchecks without mtls, verify the gcp loadbalancer ip here using
			//  ip =  net.ParseIP(ci.Conn.RemoteAddr().String())  in  ["35.191.0.0/16","130.211.0.0/22"]

			// return &tls.Config{
			// 	NextProtos: []string{"h2", "http/1.1"},
			// 	MinVersion: tls.VersionTLS13,
			// 	GetCertificate: func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// 		return &default_server_certs, nil
			// 	},
			// }, nil
			return nil, fmt.Errorf("SNI not recognized %s", ci.ServerName)
		},
	}

	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	logger.Println("Starting HTTP Server..")

	err = server.ListenAndServeTLS("", "")
	if err != nil {
		logger.Printf("Error Starting TLS Server %v\n", err)
		quit <- true
		runtime.Goexit()
	}
	quit <- true
	logger.Println("Shutting down server")
}
