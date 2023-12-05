package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"

	csclaims "github.com/salrashid123/confidential_space/claims"
)

var (
	clientCertRootCA = flag.String("clientCertRootCA", "certs/tls-ca-chain.pem", "Root CA of the client cert")
	serverCert       = flag.String("serverCert", "certs/server.crt", "Server Certificate to use")
	serverKey        = flag.String("serverKey", "certs/server.key", "Server cert key")
	audience         = flag.String("audience", "https://server.domain.com", "JWT Audience Claim to check")

	awsRegion          = flag.String("awsRegion", "us-east-1", "AWS Region")
	awsRoleArn         = flag.String("awsRoleArn", "arn:aws:iam::291738886548:role/gcpsts", "ARN of the role to use")
	awsSessionName     = flag.String("awsSessionName", "mysession", "Name of the session to use")
	awsAccessKeyID     = flag.String("awsAccessKeyID", "AKIAUH3-redacted", "AWS access Key ID")
	awsSecretAccessKey = flag.String("awsSecretAccessKey", "lIs1yCocQYKX-redacted", "AWS SecretKey")

	jwtSet *jwk.Set
)

type tokenPayload struct {
	jwt.RegisteredClaims
	UseAssumeRole bool   `json:"use_assume_role"`
	AccessKeyID   string `json:"access_key_id"`
	RoleArn       string `json:"role_arn"`
	Region        string `json:"region"`
	Duration      uint64 `json:"duration"`
	SessionName   string `json:"session_name"`
}

type tokenRequest struct {
	TokenJWT       string `json:"token_jwt"`
	AttestationJWT string `json:"attestation_jwt"`
}

type tokenResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	//jwksURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	jwksURL = "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs"
	RFC3339 = "2006-01-02T15:04:05Z07:00"

	// https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
	// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
	ipPolicy = `{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action":["s3:ListObjectsV2", "s3:ListBucket"],
				"Resource": ["arn:aws:s3:::mineral-minutia"],				
				"Condition": {
					"Bool": {
						"aws:ViaAWSService": "false"
					},
					"IpAddress": {
						"aws:SourceIp": "108.51.25.168"
					}
				}
			}
		]
	}`
)

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	ekm []byte
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ekm, err := r.TLS.ExportKeyingMaterial("my_nonce", nil, 32)
		if err != nil {
			log.Printf("EKM not found")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("EKM my_nonce from TLS: %s\n", hex.EncodeToString(ekm))
		event := &event{
			ekm: ekm,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)

	var post tokenRequest

	err := json.NewDecoder(r.Body).Decode(&post)
	if err != nil {
		log.Printf("Error parsing POST data")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jwt.MarshalSingleStringAsArray = true
	gcpIdentityDoc := &csclaims.Claims{}

	_, err = jwt.ParseWithClaims(post.AttestationJWT, gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
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
		log.Printf("Error parsing  JWT %v\n", err)
		http.Error(w, "Error parsing  JWT %v\n", http.StatusBadRequest)
		return
	}

	if len(gcpIdentityDoc.Audience) != 1 {
		log.Printf("Expected one audience value")
		http.Error(w, "Expected one audience value", http.StatusBadRequest)
		return
	}
	if gcpIdentityDoc.Audience[0] != *audience {
		log.Printf("Audience incorrect provided, expected %s  got %s", *audience, gcpIdentityDoc.Audience[0])
		http.Error(w, "Incorrect audience provided", http.StatusBadRequest)
		return
	}

	if len(gcpIdentityDoc.EATNonce) != 2 {
		log.Printf("Error ekm not provided in jwt")
		http.Error(w, "Error ekm not provided in jwt", http.StatusBadRequest)
		return
	}

	log.Printf("EKM value from header %s\n", gcpIdentityDoc.EATNonce[0])
	if gcpIdentityDoc.EATNonce[0] != hex.EncodeToString(val.ekm) {
		http.Error(w, "Error: ekm tls value does not match header", http.StatusBadRequest)
		return
	}
	log.Println("EKM value matches header")

	h := sha256.New()
	h.Write([]byte(post.TokenJWT))
	bs := h.Sum(nil)

	if hex.EncodeToString(bs) != gcpIdentityDoc.EATNonce[1] {
		log.Printf("Error: hash of jwt_token  does not match eat_nonce[1], got %s, expected %s", string(bs), gcpIdentityDoc.EATNonce[1])
		http.Error(w, "Error: hash of jwt_token  does not match eat_nonce[1], got", http.StatusBadRequest)
		return
	}

	// TODO, verify all the other claims like image_hash, SEV status, startup parameters, project, etc

	tokp := &tokenPayload{}
	// parser := jwt.NewParser()
	// _, _, err = parser.ParseUnverified(post.TokenJWT, tokp)
	// if err != nil {
	// 	fmt.Printf("Error ekm not provided in jwt %v", err)
	// 	http.Error(w, err.Error(), http.StatusBadRequest)
	// 	return
	// }

	_, err = jwt.ParseWithClaims(post.TokenJWT, tokp, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return val.ekm, nil
	})
	if err != nil {
		log.Printf("Error validating token_jwt %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	creds := credentials.NewStaticCredentials(*awsAccessKeyID, *awsSecretAccessKey, "")

	session, err := session.NewSession(&aws.Config{
		Credentials: creds,
	})
	if err != nil {
		log.Printf("Error creating aws session %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	conf := &aws.Config{
		Region:      aws.String(*awsRegion),
		Credentials: creds,
	}
	stsService := sts.New(session, conf)
	if tokp.UseAssumeRole {
		log.Println("AssumeRole")
		params := &sts.AssumeRoleInput{
			RoleArn:         aws.String(tokp.RoleArn),
			RoleSessionName: aws.String(tokp.SessionName), //aws.String(strconv.FormatUint(gcpIdentityDoc.Submods.GCE.InstanceID, 10)),
			DurationSeconds: aws.Int64(int64(tokp.Duration)),
			//Policy:          aws.String(ipPolicy),
		}
		resp, err := stsService.AssumeRole(params)
		if err != nil {
			log.Printf("Error assuming role %v", err)
			http.Error(w, fmt.Sprintf("Error assuming role: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(&tokenResponse{
			AccessKeyId:     *resp.Credentials.AccessKeyId,
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
			Expiration:      resp.Credentials.Expiration.Format(RFC3339),
		})

	} else {
		log.Println("GetSessionToken")
		resp, err := stsService.GetSessionToken(&sts.GetSessionTokenInput{
			DurationSeconds: aws.Int64(int64(tokp.Duration)),
		})
		if err != nil {
			log.Printf("Error getting session token role %v", err)
			http.Error(w, fmt.Sprintf("Error assuming role: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(&tokenResponse{
			AccessKeyId:     *resp.Credentials.AccessKeyId,
			SecretAccessKey: *resp.Credentials.SecretAccessKey,
			SessionToken:    *resp.Credentials.SessionToken,
			Expiration:      resp.Credentials.Expiration.Format(RFC3339),
		})

	}

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()

	if *awsAccessKeyID == "" || *awsSecretAccessKey == "" || *awsRegion == "" {
		log.Println("Error awsAccessKeyID,awsSecretAccessKey,awsRegion cannot be null")
		os.Exit(1)
	}
	default_server_certs, err := tls.LoadX509KeyPair(*serverCert, *serverKey)
	if err != nil {
		log.Printf("Error reading certs %v\n", err)
		os.Exit(1)
	}

	client1_root, err := os.ReadFile(*clientCertRootCA)
	if err != nil {
		log.Printf("Error client certs %v\n", err)
		os.Exit(1)
	}

	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		log.Printf("Error reading jwks %v\n", err)
		os.Exit(1)
	}

	client_cert_pool := x509.NewCertPool()
	client_cert_pool.AppendCertsFromPEM(client1_root)

	router := mux.NewRouter()
	router.Methods(http.MethodPost).Path("/token").HandlerFunc(tokenHandler)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{default_server_certs},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    client_cert_pool,
	}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Printf("Unable to start Server %v", err)

}
