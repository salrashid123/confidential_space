package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	creds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"

	jwt "github.com/golang-jwt/jwt/v5"

	// if you want to build and run this in confidential space, remove the test token
	// and use func (s *EKMProvider) getCustomAttestation(tokenRequest customToken)
	tk "github.com/salrashid123/confidential_space/misc/testtoken"
)

const (
	EKMProviderName  = "EKMProvider"
	refreshTolerance = 60
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
	RFC3339 = "2006-01-02T15:04:05Z07:00"
)

type CredConfig struct {
	STSEndpointHost      string
	STSEndpoint          string
	Audience             string
	STSSNI               string
	AttestationTokenPath string
	UseMTLS              bool
	TrustCA              string
	ClientCert           string
	ClientKey            string
	AWSAccessKeyID       string
	AWSRoleArn           string
	AWSRegion            string
	Duration             uint64
	AWSSessionName       string
	UseAssumeRole        bool
}

var (
	stsOutput *sts.AssumeRoleWithWebIdentityOutput
	tlsConfig *tls.Config
)

type EKMProvider struct {
	identityInput sts.AssumeRoleWithWebIdentityInput
	cfg           CredConfig
	expiration    time.Time
}

func NewEKMAWSCredentials(cfg CredConfig) (creds.Credentials, error) {

	if cfg.STSEndpointHost == "" || cfg.STSEndpoint == "" || cfg.TrustCA == "" || cfg.Audience == "" {
		return creds.Credentials{}, fmt.Errorf("--host -audience --endpoint --trust-ca cannot be null")
	}

	if cfg.UseAssumeRole && (cfg.AWSSessionName == "" || cfg.AWSRoleArn == "") {
		return creds.Credentials{}, fmt.Errorf("-aws-session-name cannot be null if --use-assume-role=true")
	}

	if cfg.Duration < 900 {
		return creds.Credentials{}, fmt.Errorf("duration cannot be less than 900")
	}

	caCert, err := os.ReadFile(cfg.TrustCA)
	if err != nil {
		return creds.Credentials{}, fmt.Errorf("ekm-jwt-credential:  Error loading trust ca %v\n", err)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)
	tlsConfig = &tls.Config{
		ServerName: cfg.STSSNI,
		RootCAs:    serverCertPool,
		MinVersion: tls.VersionTLS13,
	}

	if cfg.UseMTLS {
		certs, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return creds.Credentials{}, fmt.Errorf("ekm-jwt-credential:  Error loading client certs %v\n", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certs}
	}

	return *creds.NewCredentials(&EKMProvider{cfg: cfg}), nil
}

func (s *EKMProvider) Retrieve() (creds.Value, error) {

	// setup a conn and get the EKM value
	conn, err := tls.Dial("tcp", s.cfg.STSEndpointHost, tlsConfig)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error dialing %v\n", err)
	}
	cs := conn.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error getting ekm %v\n", err)
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
		UseAssumeRole: s.cfg.UseAssumeRole,
		AccessKeyID:   s.cfg.AWSAccessKeyID,
		RoleArn:       s.cfg.AWSRoleArn,
		Region:        s.cfg.AWSRegion,
		Duration:      s.cfg.Duration,
		SessionName:   s.cfg.AWSSessionName,
	}

	// you can send this as-is but what i did is just issue a JWT for the payload and used the ekm to sign
	//  theres no real benefit to issuing a signed JWT for the tokenPayload since anyone can see what signed it given the attestation_jwt's nonce
	//  but i did it here anyway...

	// token := jwt.NewWithClaims(jwt.SigningMethodNone, p)
	// tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr,"ekm-jwt-credential:  Error signing jwt with EKM %v\n", err)
	// 	os.Exit(1)
	// }

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, p)
	tokenString, err := token.SignedString(ekm)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error signing jwt with EKM %v\n", err)
	}

	// now hash the token_jwt
	h := sha256.New()
	h.Write([]byte(tokenString))
	bs := h.Sum(nil)

	// set the hash as the second value in the attestation_jwt
	// this will ensure the jwt we sent in matches what was actually in use inside conf_space
	// also embed the ekm value.
	//  by convention, i'm setting eat_nonce[0]=ekm and eat_nonce[1]=sha256(tokenString)
	tts := &tk.CustomToken{
		Audience:  s.cfg.Audience,
		Nonces:    []string{hex.EncodeToString(ekm), hex.EncodeToString(bs)},
		TokenType: tk.TOKEN_TYPE_OIDC,
	}

	// now get the token using the fake testprovider
	customTokenValue, err := tk.GetCustomAttestation(tts)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error creating Custom JWT %v", err)
	}

	// if you deploy to prod, use the following on confidential space
	// customTokenValue, err := getCustomAttestation(tts)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ekm-jwt-credential:  Error creating Custom JWT %v", err)
	// 	os.Exit(1)
	// }

	// create a request and supply the token_jwt and attestation_jwt
	tt := &tokenRequest{
		TokenJWT:       tokenString,
		AttestationJWT: customTokenValue,
	}
	body, err := json.Marshal(tt)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error marshalling POST JSON %v\n", err)
	}

	resp, err := client.Post(s.cfg.STSEndpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential:  Error posting to TEE %v\n", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		htmlData, err := io.ReadAll(resp.Body)
		if err != nil {
			return creds.Value{}, fmt.Errorf("ekm-jwt-credential: Error reading response from server %v", err)
		}
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential: Error getting response from server %s", htmlData)
	}

	// we got a valid response so unmarshal it and output the data back
	var post tokenResponse
	err = json.NewDecoder(resp.Body).Decode(&post)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential: Error unmarshallnng response%v\n", err)
	}

	v := creds.Value{
		AccessKeyID:     post.AccessKeyId,
		SecretAccessKey: post.SecretAccessKey,
		SessionToken:    post.SessionToken,
	}
	if v.ProviderName == "" {
		v.ProviderName = EKMProviderName
	}
	t, err := time.Parse(RFC3339, post.Expiration)
	if err != nil {
		return creds.Value{}, fmt.Errorf("ekm-jwt-credential: Error parsing time string %v", err)
	}
	s.expiration = t
	return v, nil
}

func (s *EKMProvider) IsExpired() bool {
	if time.Now().Add(time.Second * time.Duration(refreshTolerance)).After(s.expiration) {
		return true
	}
	return false
}

func (s *EKMProvider) ExpiresAt() time.Time {
	return s.expiration
}

type customToken struct {
	Audience string   `json:"audience"`
	Nonces   []string `json:"nonces"` // each nonce must be min 64bits
}

func (s *EKMProvider) getCustomAttestation(tokenRequest customToken) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", s.cfg.AttestationTokenPath)
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
