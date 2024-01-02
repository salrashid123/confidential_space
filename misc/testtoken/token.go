package testtoken

/*
	Generates a test token for GCP Confidential Space

	The the signer is a  "fake oidc" key pair from:
	   https://github.com/salrashid123/diy_oidc
*/
import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"
	csclaims "github.com/salrashid123/confidential_space/claims"
)

const (
	rsaKeyID  = "rsaKeyID_1"
	rsaPubKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqrpBHkLN4vT6g279KYT
nnbKWHIEa+fK04wlamlrALQpV6QGfIrPwSgU/ElRFpsPJYWxCvEtYS01lBC70IeA
hObR5DY9Z+jTvhk1tA+VrxyEhAHLuCuCsAPLow4ZSJ+aB0vZuUtaV9+qO+0gyJEG
9y/5FKT51Tbr0INtjDASH43seoQtsPDG2tnKEj9r7jOLUNehj5j4Dgv+sJMGe3Ey
Klw7p6vsIhsU23v0VrTxdHGuelzplxCUQJoPRSxgepYyVmfrB12XJ5uJtLhYwuTb
Fb3BIUyswBtxtGcigvk/ftkuSQjubiXe8UtltBI7INfs7vmAVuQr7YN8Alni4Z3B
eQIDAQAB
-----END PUBLIC KEY-----`

	rsaPrivKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqqrpBHkLN4vT6g279KYTnnbKWHIEa+fK04wlamlrALQpV6QG
fIrPwSgU/ElRFpsPJYWxCvEtYS01lBC70IeAhObR5DY9Z+jTvhk1tA+VrxyEhAHL
uCuCsAPLow4ZSJ+aB0vZuUtaV9+qO+0gyJEG9y/5FKT51Tbr0INtjDASH43seoQt
sPDG2tnKEj9r7jOLUNehj5j4Dgv+sJMGe3EyKlw7p6vsIhsU23v0VrTxdHGuelzp
lxCUQJoPRSxgepYyVmfrB12XJ5uJtLhYwuTbFb3BIUyswBtxtGcigvk/ftkuSQju
biXe8UtltBI7INfs7vmAVuQr7YN8Alni4Z3BeQIDAQABAoIBAG2SZSA2BnmXEGsI
fk/IAHiQk8DNEwGkQ5gmNi9nlwdQo+pcqL108YV1kmOXPrRgwQy6FLyNszDcsbVq
OOrc1Cp/duop2KrJ1IgL72q3RsaybHHEJWMMrE8NYMRC3QC/V0iv7g0Ez+/y7Xyj
9ZRPaEVzS1txv+Sf6i5o8wA6LKiMjMDYLFKxfzhjdakghshSNobuP3Vrw+KthHtr
96bTESBD/nvBJolZs8wiFa/DcXGrgoh2htZhuxlZCTsEMWT8TCETsZohR5NUZ0wL
yD2+KXwIydp2NIkunfKT7EISaZ1fNpPPjCMskpEL675yQklluo+D6qj9W1HDRkYk
zo7PEMECgYEA4cQddq3H6CftnLrg2QcDT3jOhxOnHCT31oQBHZbUNLpQ38fHp6BX
YnQ0bH32eFHYLw9TEdYhwebp2rLruPjy25r8buRK+YXkhNL404ooo9dC1XhX7oVz
6aMVq6yHSlNsNrbTXH1CChP/9hgPR5osfeUP8u2Utp7exQg9qE/zmr0CgYEAwYXe
J0LWmXknnqZ/8Ld7ZKZiL7U9E5QV8Epz9OYCHDQevRoh03iWhUWJeP1ps0sp1rb8
zW3kUs5iCzj54UylcwcPYLK9hgVsYtgLFbNas9XwdNPQH0OdlUBAtAIvyZudIVCb
vJyCcuw/KlUIbDDI23n3/sqiM60H0H9u+FOFy20CgYAV7vap1AJK5K4p/uHfU9YX
f3YZG2itzE2jspllJYUiRkObKg6Uk3hJ4V5CeA5c7B6jm8qHPhVzgBqSG7XY956o
hSsnHtjF2yMzYEe6TX7bRAuDL7jjPGXhee2eCxntt6MYwbRRFP44em7wmq/JVgoi
hQGCqWA8Sbz8yWssEfBpxQKBgGgc1wmUQdPLhG8r8ETW0YGyqbw06yjvUGY4B+5H
F/eIaskdl/knNQN6B52Z6BXXaCjlxVfXuTB7a+/RtU1qaNBbigBh6OiDXm5HAJ+q
IDAD9xtDIQLQ46R6LtUpIAB8wao8raxpHx0o0Eq7+I4MKOM62RqwdVcLzdpz1IWw
mZh5AoGAeVkFstY9lmcdEi2rHUAsR2WMOnzYP4WS+/dYIMsXVryNVa/obbjwz94N
rWWOI9aKV6wvK+CIzHsI7hsFw7aF0S2x1gg4RvtxDgHCMbgI3t8tdCtph7cmDKNp
W1NUvPpHH7t1YenNODRZSEo/ETn69WX6i0kV4BNI64+cU60pUwQ=
-----END RSA PRIVATE KEY-----`

	jwksURL = "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs"
	RFC3339 = "2006-01-02T15:04:05Z07:00"
)

const (
	TOKEN_TYPE_OIDC        string = "OIDC"
	TOKEN_TYPE_UNSPECIFIED string = "UNSPECIFIED"
)

// https://cloud.google.com/confidential-computing/confidential-vm/docs/reference/cs-token-claims#supported-claims
type CustomToken struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

type key struct {
	SigningMethod jwt.SigningMethod
	PrivateKey    interface{}
	PublicKey     interface{}
	HMACKey       []byte
}

func GetAttestation(csclaims csclaims.Claims) (string, error) {

	for _, v := range csclaims.EATNonce {
		if len([]byte(v)) < 9 || len([]byte(v)) > 74 {
			return "", errors.New("Custom nonce must be between 10 and 74 bytes")
		}
	}
	if len(csclaims.EATNonce) > 6 {
		return "", errors.New("Maximum  of 6 Custom nonces are allowed")
	}

	block, _ := pem.Decode([]byte(rsaPrivKey))
	if block == nil {
		return "", fmt.Errorf("Error decoding private key\n")
	}
	privKeyRSA, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	keys := make(map[string]*key)
	keys[rsaKeyID] = &key{
		SigningMethod: jwt.SigningMethodRS256,
		PrivateKey:    privKeyRSA,
		PublicKey:     privKeyRSA.PublicKey,
	}
	token := jwt.NewWithClaims(keys[rsaKeyID].SigningMethod, csclaims)

	token.Header["kid"] = rsaKeyID
	return token.SignedString(keys[rsaKeyID].PrivateKey)
}

func GetCustomAttestation(tokenRequest *CustomToken) (string, error) {

	for _, v := range tokenRequest.Nonces {
		if len([]byte(v)) < 9 || len([]byte(v)) > 74 {
			return "", errors.New("Custom nonce must be between 10 and 74 bytes")
		}
	}
	if len(tokenRequest.Nonces) > 6 {
		return "", errors.New("Maximum  of 6 Custom nonces are allowed")
	}

	block, _ := pem.Decode([]byte(rsaPrivKey))
	if block == nil {
		return "", fmt.Errorf("Error decoding private key")
	}
	privKeyRSA, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	keys := make(map[string]*key)
	keys[rsaKeyID] = &key{
		SigningMethod: jwt.SigningMethodRS256,
		PrivateKey:    privKeyRSA,
		PublicKey:     privKeyRSA.PublicKey,
	}

	now := time.Now()
	expAt := time.Now().Add(time.Hour)
	token := jwt.NewWithClaims(keys[rsaKeyID].SigningMethod, csclaims.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
			Audience:  jwt.ClaimStrings{tokenRequest.Audience},
			Subject:   "https://www.googleapis.com/compute/v1/projects/vegas-codelab-5/zones/us-central1-a/instances/vm1",
			ExpiresAt: jwt.NewNumericDate(expAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Dbgstat:               "disabled-since-boot",
		GoogleServiceAccounts: []string{"operator-svc-account@vegas-codelab-5.iam.gserviceaccount.com"},
		HardwareModel:         "GCP_AMD_SEV",
		OEMID:                 11129,
		Secboot:               true,
		EATNonce:              tokenRequest.Nonces,
		Submods: csclaims.SubmodClaims{
			ConfidentialSpace: csclaims.ConfidentialSpaceClaims{
				SupportAttributes: []string{"LATEST", "STABLE", "USABLE"},
			},
			Container: csclaims.ContainerClaims{
				Args:        []string{"./server"},
				CmdOverride: []string{},
				Env: map[string]string{
					"HOSTNAME":      "vm1",
					"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
				},
				EnvOverride:    map[string]string{},
				ImageDigest:    "sha256:9ec06569f1c169d4c5b380c64b803d287468d95429dab4e4449842f93a252049",
				ImageID:        "sha256:d1236700e3ba8ecaff2f26cbfdd8f1d00f22ed5f133d2b1f2e00239c0824664b",
				ImageReference: "docker.io/salrashid123/myimage@sha256:9ec06569f1c169d4c5b380c64b803d287468d95429dab4e4449842f93a252049",
				ImageSignatures: []csclaims.ImageSignatures{
					{
						KeyID:              "2b20bfe7bb76a7405dfcc75193e7768c41c1fffa28aeabc15e7ad21b0fdc9a89",
						Signature:          "MEUCIAoXDplWGo0Tn2K1E/Ny2kiTHhdN1+i06d7Pu/FVN1EkAiEA2ggnIc7AVnPcmM5R/7w1hNshpOfpY0d7GJ3+bJJwcSA=",
						SignatureAlgorithm: "ECDSA_P256_SHA256",
					},
				},
				RestartPolicy: "Never",
			},
			GCE: csclaims.GCEClaims{
				InstanceID:    6920867375712861823,
				InstanceName:  "vm1",
				ProjectID:     "vegas-codelab-5",
				ProjectNumber: 75457521745,
				Zone:          "us-central1-a",
			},
		},
		SoftwareName:    "CONFIDENTIAL_SPACE",
		SoftwareVersion: []string{"1"},
		Tee: csclaims.TEEClaims{
			Container: csclaims.ContainerClaims{
				Args:           []string{},
				CmdOverride:    []string{},
				Env:            map[string]string{},
				EnvOverride:    map[string]string{},
				ImageDigest:    "",
				ImageID:        "",
				ImageReference: "",
				RestartPolicy:  "",
			},
			GCE:      csclaims.GCEClaims{},
			Platform: csclaims.PlatformClaims{},
			Version: csclaims.VersionClaims{
				Major: 0,
				Minor: 0,
			},
		},
	})
	token.Header["kid"] = rsaKeyID
	return token.SignedString(keys[rsaKeyID].PrivateKey)
}

func VerifyToken(rawJWT string) (*jwt.Token, error) {

	jwtSet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		log.Printf("Error reading jwks %v\n", err)
		os.Exit(1)
	}

	jwt.MarshalSingleStringAsArray = true
	gcpIdentityDoc := &csclaims.Claims{}

	token, err := jwt.ParseWithClaims(rawJWT, gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
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
		return nil, err
	}
	return token, nil
}
