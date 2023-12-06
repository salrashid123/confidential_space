package credential

import (
	"bytes"
	"context"
	"crypto/sha1"
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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	jwt "github.com/golang-jwt/jwt/v5"
	// if you want to build and run this in confidential space, remove the test token
	// and use func (s *EKMProvider) getCustomAttestation(tokenRequest customToken)
	//tk "github.com/salrashid123/confidential_space/misc/testtoken"
)

type tokenPayload struct {
	jwt.RegisteredClaims
	Tenant string `json:"tenant,omitempty"` // optionally allow the client to specify the tenant and appid, this is currently ignored in this implementation
	AppID  string `json:"appid,omitempty"`
	Scope  string `json:"scope"`
}

type tokenRequest struct {
	TokenJWT       string `json:"token_jwt"`
	AttestationJWT string `json:"attestation_jwt"`
}

type rpctokenResponse struct {
	ExpiresOn   string `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	ExtExpiresIn int64  `json:"ext_expires_in,omitempty"`
}

const (
	ISO8601 = "2006-01-02T15:04:05-0700"
	RFC3339 = "2006-01-02T15:04:05Z07:00"
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

type EKMAZCredentialOptions struct {
	azcore.ClientOptions
	ClientID string
	Audience string
	TenantID string

	STSEndpointHost      string
	STSEndpoint          string
	STSSNI               string
	AttestationTokenPath string
	UseMTLS              bool
	TrustCA              string
	ClientCert           string
	ClientKey            string
	Scope                string
	SendCertificateChain bool
}

type EKMAZCredential struct {
	cred  azcore.TokenCredential
	copts EKMAZCredentialOptions
}

var (
	tlsConfig *tls.Config
)

func NewEKMAZCredentials(options *EKMAZCredentialOptions) (*EKMAZCredential, error) {

	if options.STSEndpointHost == "" || options.STSEndpoint == "" || options.TrustCA == "" {
		return nil, fmt.Errorf("--host -audience --endpoint --trust-ca cannot be null")
	}

	caCert, err := os.ReadFile(options.TrustCA)
	if err != nil {
		return nil, fmt.Errorf("ekm-jwt-credential:  Error loading trust ca %v\n", err)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)
	tlsConfig = &tls.Config{
		ServerName: options.STSSNI,
		RootCAs:    serverCertPool,
		MinVersion: tls.VersionTLS13,
	}

	if options.UseMTLS {
		certs, err := tls.LoadX509KeyPair(options.ClientCert, options.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("ekm-jwt-credential:  Error loading client certs %v\n", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certs}
	}

	return &EKMAZCredential{
		copts: *options,
	}, nil
}

func (c *EKMAZCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {

	if len(opts.Scopes) != 1 {
		return azcore.AccessToken{}, fmt.Errorf("Scopes provided must be exactly one, got %v", opts.Scopes)
	}

	// setup a conn and get the EKM value
	conn, err := tls.Dial("tcp", c.copts.STSEndpointHost, tlsConfig)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error dialing %v\n", err)
	}
	cs := conn.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial("my_nonce", nil, 32)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ekm-jwt-credential:  Error getting ekm %v\n", err)
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
		Tenant: c.copts.TenantID,
		AppID:  c.copts.ClientID,
		Scope:  opts.Scopes[0],
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
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error signing jwt with EKM %v\n", err)
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
	// 	Audience:  c.copts.Audience,
	// 	Nonces:    []string{hex.EncodeToString(ekm), hex.EncodeToString(bs)},
	// 	TokenType: tk.TOKEN_TYPE_OIDC,
	// }

	// // now get the token using the fake testprovider
	// customTokenValue, err := tk.GetCustomAttestation(tts)
	// if err != nil {
	// 	return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error creating Custom JWT %v", err)
	// }

	// if you deploy to prod, use the following on confidential space
	tts := customToken{
		Audience:  c.copts.Audience,
		Nonces:    []string{hex.EncodeToString(ekm), hex.EncodeToString(bs)},
		TokenType: TOKEN_TYPE_OIDC,
	}
	customTokenValue, err := c.getCustomAttestation(tts)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error creating Custom JWT %v", err)
	}

	// create a request and supply the token_jwt and attestation_jwt
	tt := &tokenRequest{
		TokenJWT:       tokenString,
		AttestationJWT: customTokenValue,
	}
	body, err := json.Marshal(tt)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error marshalling POST JSON %v\n", err)
	}

	resp, err := client.Post(c.copts.STSEndpoint, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential:  Error posting to TEE %v\n", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		htmlData, err := io.ReadAll(resp.Body)
		if err != nil {
			return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential: Error reading response from server %v", err)
		}
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential: Error getting response from server %s", htmlData)
	}

	// we got a valid response so unmarshal it and output the data back
	var post rpctokenResponse
	err = json.NewDecoder(resp.Body).Decode(&post)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential: Error unmarshallnng response%v\n", err)
	}

	t, err := time.Parse(RFC3339, post.ExpiresOn)
	if err != nil {
		return azcore.AccessToken{}, fmt.Errorf("ekm-jwt-credential: Error parsing time %v\n", err)
	}

	r := azcore.AccessToken{
		Token:     post.AccessToken,
		ExpiresOn: t,
	}
	return r, nil
}

func (c *EKMAZCredential) getCustomAttestation(tokenRequest customToken) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", c.copts.AttestationTokenPath)
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

func thumbprint(cert *x509.Certificate) []byte {
	/* #nosec */
	a := sha1.Sum(cert.Raw)
	return a[:]
}

var _ azcore.TokenCredential = (*EKMAZCredential)(nil)
