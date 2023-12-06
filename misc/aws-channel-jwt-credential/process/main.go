package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"fmt"
	"os"

	jwt "github.com/golang-jwt/jwt/v5"

	"flag"

	"github.com/google/uuid"
	//tk "github.com/salrashid123/confidential_space/misc/testtoken"
)

const ()

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

// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
type processCredentialsResponse struct {
	Version         int    `json:"Version"`
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

const (
	ISO8601 = "2006-01-02T15:04:05-0700"
)

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
)

type customToken struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

type credConfig struct {
	flSTSEndpointHost      string
	flSTSEndpoint          string
	flAudience             string
	flSTSSNI               string
	flAttestationTokenPath string
	flSUseMTLS             bool
	flSTrustCA             string
	flSTSClientCert        string
	flSTSClientKey         string
	flAWSAccessKeyID       string
	flAWSRoleArn           string
	flAWSRegion            string
	flDuration             uint64
	flAWSSessionName       string
	flUseAssumeRole        bool
}

var (
	cfg = &credConfig{}
)

func main() {
	flag.StringVar(&cfg.flSTSEndpointHost, "host", "", "(required) STS Server host:port")
	flag.StringVar(&cfg.flSTSEndpoint, "endpoint", "", "(required) STS Server endpoint")
	flag.StringVar(&cfg.flAudience, "audience", "", "(required) Token Audience")
	flag.StringVar(&cfg.flSTSSNI, "sts-sni", "", "STS Server endpoint SNI")
	flag.StringVar(&cfg.flSTrustCA, "trust-ca", "", "Server Trust CA")
	flag.StringVar(&cfg.flSTSClientCert, "cert", "", "(required if --use-mtsl=true) Client Cert")
	flag.StringVar(&cfg.flSTSClientKey, "key", "", "(required if --use-mtsl=true) Client Key")
	flag.BoolVar(&cfg.flSUseMTLS, "use-mtls", false, "Use mTLS to connect to STS Server")
	flag.StringVar(&cfg.flAttestationTokenPath, "attestation_token_path", "/run/container_launcher/teeserver.sock", "Path to Attestation Token file")
	flag.Uint64Var(&cfg.flDuration, "duration", uint64(900), "(optional) Duration value (min 900)")
	flag.StringVar(&cfg.flAWSRegion, "aws-region", "", "(optional) AWS Region")
	flag.StringVar(&cfg.flAWSAccessKeyID, "aws-access-key-id", "", "(optional) AWS access key id")

	flag.BoolVar(&cfg.flUseAssumeRole, "use-assume-role", false, "(optional) Use Assume Role or not")
	flag.StringVar(&cfg.flAWSSessionName, "aws-session-name", fmt.Sprintf("gcp-%s", uuid.New().String()), "(required if --use-assume-role=true)  AWS SessionName")
	flag.StringVar(&cfg.flAWSRoleArn, "aws-arn", "", "(required if --use-assume-role=true) AWS ARN Value")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Invalid Argument error: "+s, v...)
		os.Exit(1)
	}

	if cfg.flSTSEndpointHost == "" || cfg.flSTSEndpoint == "" || cfg.flSTrustCA == "" || cfg.flAudience == "" {
		argError("--host -audience --endpoint --trust-ca cannot be null")
	}

	if cfg.flUseAssumeRole && (cfg.flAWSSessionName == "" || cfg.flAWSRoleArn == "") {
		argError("-aws-session-name cannot be null if --use-assume-role=true")
	}

	if cfg.flDuration < 900 {
		argError("duration must be min 900s")
	}

	caCert, err := os.ReadFile(cfg.flSTrustCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error loading trust ca %v\n", err)
		os.Exit(1)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		ServerName: cfg.flSTSSNI,
		RootCAs:    serverCertPool,
		MinVersion: tls.VersionTLS13,
	}

	if cfg.flSUseMTLS {
		certs, err := tls.LoadX509KeyPair(cfg.flSTSClientCert, cfg.flSTSClientKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error loading client certs %v\n", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{certs}
	}

	// setup a conn and get the EKM value

	conn, err := tls.Dial("tcp", cfg.flSTSEndpointHost, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error dialing %v\n", err)
		os.Exit(1)
	}
	cs := conn.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error getting ekm %v\n", err)
		os.Exit(1)
	}

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return conn, nil
		},
	}
	client := http.Client{
		Transport: tr,
	}

	// construct the actual request parameters to send
	p := tokenPayload{
		UseAssumeRole: cfg.flUseAssumeRole,
		AccessKeyID:   cfg.flAWSAccessKeyID,
		RoleArn:       cfg.flAWSRoleArn,
		Region:        cfg.flAWSRegion,
		Duration:      cfg.flDuration,
		SessionName:   cfg.flAWSSessionName,
	}

	// you can send this as-is but what i did is just issue a JWT for the payload and used the ekm to sign
	//  theres no real benefit to issuing a signed JWT for the tokenPayload since anyone can see what signed it given the attestation_jwt's nonce
	//  but i did it here anyway...

	// token := jwt.NewWithClaims(jwt.SigningMethodNone, p)
	// tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr,"aws-channel-jwt-process-credential:  Error signing jwt with EKM %v\n", err)
	// 	os.Exit(1)
	// }

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, p)
	tokenString, err := token.SignedString(ekm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error signing jwt with EKM %v\n", err)
		os.Exit(1)
	}

	// now hash the token_jwt
	h := sha256.New()
	h.Write([]byte(tokenString))
	bs := h.Sum(nil)

	// set the hash as the second value in the attestation_jwt
	// this will ensure the jwt we sent in matches what was actually in use inside conf_space
	// also embed the ekm value.
	//  by convention, i'm setting eat_nonce[0]=ekm and eat_nonce[1]=sha256(tokenString)
	// tts := &tk.CustomToken{
	// 	Audience:  cfg.flAudience,
	// 	Nonces:    []string{hex.EncodeToString(ekm), hex.EncodeToString(bs)},
	// 	TokenType: tk.TOKEN_TYPE_OIDC,
	// }

	// // now get the token
	// customTokenValue, err := tk.GetCustomAttestation(tts)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error creating Custom JWT %v", err)
	// 	os.Exit(1)
	// }

	tts := customToken{
		Audience:  cfg.flAudience,
		Nonces:    []string{hex.EncodeToString(ekm), hex.EncodeToString(bs)},
		TokenType: TOKEN_TYPE_OIDC,
	}

	customTokenValue, err := getCustomAttestation(tts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error creating Custom JWT %v", err)
		os.Exit(1)
	}

	// create a request and supply the token_jwt and attestation_jwt
	tt := &tokenRequest{
		TokenJWT:       tokenString,
		AttestationJWT: customTokenValue,
	}
	body, err := json.Marshal(tt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Post(cfg.flSTSEndpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential:  Error posting to TEE %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		htmlData, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential: Error reading response from server %v", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential: Error getting response from server %s", htmlData)
		os.Exit(1)
	}

	// we got a valid response so unmarshal it and output the data back
	var post tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&post)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential: Error unmarshallnng response%v\n", err)
		os.Exit(1)
	}

	tresp := &processCredentialsResponse{
		Version:         1,
		AccessKeyId:     post.AccessKeyId,
		SecretAccessKey: post.SecretAccessKey,
		SessionToken:    post.SessionToken,
		Expiration:      post.Expiration,
	}

	m, err := json.Marshal(tresp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-channel-jwt-process-credential: Error marshalling processCredential output %v", err)
		os.Exit(1)
	}
	fmt.Println(string(m))
}

func getCustomAttestation(tokenRequest customToken) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", cfg.flAttestationTokenPath)
			},
		},
	}

	customJSON, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", err
	}

	url := "http://localhost/v1/token"
	resp, err := httpClient.Post(url, "application/json", strings.NewReader(string(customJSON)))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(tokenbytes), nil
}
