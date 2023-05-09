package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"

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

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	config                 = flag.String("config", "config.json", "Arbitrary config file")
	attestation_token_path = flag.String("attestation_token_path", "/run/container_launcher/attestation_verifier_claims_token", "Path to Attestation Token file")
	project_id             = flag.String("project_id", "", "ProjectID for pubsub subscription and logging")

	// for mtls certificates
	default_ca      = flag.String("default_ca", "root-ca-operator.crt", "Operator RootCA Chain (PEM)")
	default_tls_crt = flag.String("default_tls_crt", "tee-operator.crt", "Operator TLS Certificate (PEM)")
	default_tls_key = flag.String("default_tls_key", "tee-operator.key", "Operator TLS KEY (PEM)")

	// collaborator mtls certs and keys materialized within the TEE
	collaborator1_ca      = flag.String("collaborator1_ca", "root-ca-collaborator1.crt", "Collaborator 1 RootCA Chain (PEM)")
	collaborator1_tls_crt = flag.String("collaborator1_tls_crt", "tee-collaborator1.crt", "Collaborator 1 TLS Certificate (PEM)")
	collaborator1_tls_key = flag.String("collaborator1_tls_key", "tee-collaborator1.key", "Collaborator 1 TLS KEY (PEM)")

	collaborator2_ca      = flag.String("collaborator2_ca", "root-ca-collaborator2.crt", "Collaborator 2 RootCA Chain (PEM)")
	collaborator2_tls_crt = flag.String("collaborator2_tls_crt", "tee-collaborator2.crt", "Collaborator 2 TLS Certificate (PEM)")
	collaborator2_tls_key = flag.String("collaborator2_tls_key", "tee-collaborator2.key", "Collaborator 2 TLS KEY (PEM)")

	// map to hold all the users currently found and the number of times
	// they've been sent
	users = map[string]int32{}

	logger *log.Logger
	mu     sync.Mutex
)

const (
	subscription = "cs-subscribe" // the subscription where both collaborators submit messages; you could also setup 1 topic/subscription for each collaborator as well
	jwksURL      = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	logName      = "cs-log"
)

type PostData struct {
	Key           string `json:"key"`
	Audience      string `json:"audience"`
	EncryptedData string `json:"encrypted_data"`
}

// contextKey is used to pass http middleware certificate details
type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
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

		event := &event{
			PeerCertificates: r.TLS.PeerCertificates,
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

func posthandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	// note val.PeerCertificates[0] is the leaf
	for _, c := range val.PeerCertificates {
		h := sha256.New()
		h.Write(c.Raw)
		fmt.Printf("Client Certificate hash %s\n", base64.RawURLEncoding.EncodeToString(h.Sum(nil)))
	}

	var post PostData
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
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, fmt.Sprintf("%s %d\n", u, c))
}

func main() {

	flag.Parse()

	ctx := context.Background()

	// configure a logger client
	logger = log.Default()

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

	//  Start listening to pubsub messages on background
	pubsubClient, err := pubsub.NewClient(ctx, *project_id)
	if err != nil {
		logger.Printf("Error creating pubsub client %v\n", err)
		runtime.Goexit()
	}
	defer pubsubClient.Close()

	logger.Printf("Beginning subscription: %s\n", subscription)
	sub := pubsubClient.Subscription(subscription)
	go func(ctx context.Context) {
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
			runtime.Goexit()
		}
	}(ctx)

	// start http server on main
	router := mux.NewRouter()
	router.Methods(http.MethodPost).Path("/").HandlerFunc(posthandler)
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthhandler)

	// load default server certs
	default_server_certs, err := tls.LoadX509KeyPair(*default_tls_crt, *default_tls_key)
	if err != nil {
		logger.Printf("Error loading default certificates %v\n", err)
		runtime.Goexit()
	}

	// load the CA client cert and server certificates
	// load rootCA for CA_1
	client1_root, err := ioutil.ReadFile(*collaborator1_ca)
	if err != nil {
		logger.Printf("Error loading collaborator1 ca certificate %v\n", err)
		runtime.Goexit()
	}

	client1_root_pool := x509.NewCertPool()
	client1_root_pool.AppendCertsFromPEM(client1_root)

	// load rootCA for CA_2
	client2_root, err := ioutil.ReadFile(*collaborator2_ca)
	if err != nil {
		logger.Printf("Error loading collaborator2 ca certificate %v\n", err)
		runtime.Goexit()
	}

	client2_root_pool := x509.NewCertPool()
	client2_root_pool.AppendCertsFromPEM(client2_root)

	// load the server certs issued by both ca1 and ca2, pretend these should use get loaded
	// from each collaborators's secret manager or private ca using the attestation token (similar to the KMS decryption)
	server1_cert, err := tls.LoadX509KeyPair(*collaborator1_tls_crt, *collaborator1_tls_key)
	if err != nil {
		logger.Printf("Error loading collaborator1 server certificates %v\n", err)
		runtime.Goexit()
	}

	server2_cert, err := tls.LoadX509KeyPair(*collaborator2_tls_crt, *collaborator2_tls_key)
	if err != nil {
		logger.Printf("Error loading collaborator2 server certificates %v\n", err)
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
		runtime.Goexit()
	}

	logger.Println("Shutting down server")
}
