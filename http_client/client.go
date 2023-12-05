package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	csclaims "github.com/salrashid123/confidential_space/claims"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"
)

var (
	kmsKey                               = flag.String("kmsKey", "projects/collaborator-1/locations/global/keyRings/kr1/cryptoKeys/key1", "KMS Key to use")
	audience                             = flag.String("audience", "//iam.googleapis.com/projects/248928956783/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier", "Collaborator's audience value")
	user                                 = flag.String("user", "alice", "user to submit data for")
	host                                 = flag.String("host", "", "host ip:port to connect to")
	server_name                          = flag.String("server_name", "tee.operator.com", "SNI of the server")
	ca_files                             = flag.String("ca_files", "", "RootCA Chain (PEM)")
	tls_crt                              = flag.String("tls_crt", "", "TLS Certificate (PEM)")
	tls_key                              = flag.String("tls_key", "", "TLS KEY (PEM)")
	expected_image_hash                  = flag.String("expected_image_hash", "", "Expected image_hash to verify")
	marshal_custom_token_string_as_array = flag.Bool("marshal_custom_token_string_as_array", false, "Try to parse audience and eat_token as string array even if single string")
)

const (
	jwksURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
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

func main() {
	flag.Parse()
	ctx := context.Background()

	caCert, err := os.ReadFile(*ca_files)
	if err != nil {
		fmt.Printf("Error loading ca certificate %v\n", err)
		os.Exit(1)
	}

	serverCertPool := x509.NewCertPool()
	serverCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*tls_crt, *tls_key)
	if err != nil {
		fmt.Printf("Error loading client keypair %v\n", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		ServerName:   *server_name,
		RootCAs:      serverCertPool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				c, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				fmt.Printf("                          Server Subject %s\n", c.Subject)
				fmt.Printf("                          Server Issuer %s\n", c.Issuer)
				fmt.Printf("                          Server Serial Number %s\n", c.SerialNumber)
			}
			return nil
		},
	}

	cf, err := os.ReadFile(*tls_crt)
	if err != nil {
		fmt.Printf("loading cleint certificate error :%s\n", err.Error())
		os.Exit(1)
	}

	cpb, _ := pem.Decode(cf)

	crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		fmt.Printf("error decoding certificate %s\n", err.Error())
		os.Exit(1)
	}

	clientCertHash := sha256.New()
	clientCertHash.Write(crt.Raw)

	var ekm []byte
	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, tlsConfig)
			if err != nil {
				return conn, err
			}
			err = conn.Handshake()
			if err != nil {
				return conn, err
			}
			cs := conn.ConnectionState()
			ekm, err = cs.ExportKeyingMaterial("my_nonce", nil, 32)
			if err != nil {
				return nil, fmt.Errorf("ExportKeyingMaterial failed: %v\n", err)
			}
			fmt.Printf("                          EKM my_nonce: %s\n", hex.EncodeToString(ekm))

			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip := net.ParseIP(host)
			fmt.Printf("                          Connected to IP: %s\n", ip)
			return conn, nil
		},
	}
	client := &http.Client{Transport: tr}

	// create a connection

	fmt.Println("========================== Connecting /connect ==========================")
	c := connectRequest{
		Uid: "foo",
	}
	connectBody, err := json.Marshal(c)
	if err != nil {
		fmt.Printf("Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	cr, err := client.Post(fmt.Sprintf("https://%s/connect", *host), "application/json", bytes.NewBuffer(connectBody))
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}

	connectBody, err = io.ReadAll(cr.Body)
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}
	// close now so we can reuse the same TLS conn
	err = cr.Body.Close()
	if err != nil {
		fmt.Printf("Error closing body %v\n", err)
		os.Exit(1)
	}
	var connectResp connectResponse
	err = json.Unmarshal(connectBody, &connectResp)
	if err != nil {
		fmt.Printf("Error parsing response from TEE %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("                          Status: %s\n", cr.Status)

	// now verify the Attestation JWT

	fmt.Println("                          connected; verifying attestation JWT includes EKM")

	//fmt.Printf("Raw TOKEN   [%s]\n", connectResp.AttestationJWT)
	jwtSet, err := jwk.FetchHTTP(jwksURL)
	if err != nil {
		fmt.Printf("Error reading jwks %v\n", err)
		os.Exit(1)
	}

	jwt.MarshalSingleStringAsArray = *marshal_custom_token_string_as_array
	gcpIdentityDoc := &csclaims.Claims{}

	token, err := jwt.ParseWithClaims(connectResp.AttestationJWT, gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
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
		fmt.Printf("Error parsing  JWT %v\n", err)
		os.Exit(1)
	}

	if claims, ok := token.Claims.(*csclaims.Claims); ok && token.Valid {
		fmt.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Printf("Error parsing token %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(printedClaims))

		clientHash := base64.StdEncoding.EncodeToString(clientCertHash.Sum(nil))

		for _, a := range claims.Audience {
			if a != clientHash {
				fmt.Printf("Error Audience value does not match client cert hash want %s   got %s  \n", clientHash, a)
				os.Exit(1)
			}
		}

		if *expected_image_hash != claims.Submods.Container.ImageReference {
			fmt.Printf("unexpected image hash.  Expected %s,  got %s\n", *expected_image_hash, claims.Submods.Container.ImageReference)
			os.Exit(1)
		}

		// just by this repo's convention,
		// claims.EATNonce[0] is the EKM
		// claims.EATNonce[1] is the clientCertHash

		if len(claims.EATNonce) != 2 {
			fmt.Printf("Expected eat nonce to have two values, got %d\n", len(claims.EATNonce))
			os.Exit(1)
		}

		if hex.EncodeToString(ekm) != claims.EATNonce[0] {
			fmt.Printf("TLS EKM value matches eat_nonce provided in token token, expected %s, got %s\n", hex.EncodeToString(ekm), claims.EATNonce[0])
			os.Exit(1)
		} else {
			fmt.Printf("                          EKM Match expected eat_nonce[0]=%s, got %s\n", hex.EncodeToString(ekm), claims.EATNonce[0])
		}

		if clientHash != claims.EATNonce[1] {
			fmt.Printf("eat_nonce value for clientCertHash does not match, expected eat_nonce[1]=%s, got %s\n", clientHash, claims.EATNonce[1])
			os.Exit(1)
		} else {
			fmt.Printf("                          Client certificate hash matches expected eat_nonce[1]=%s, got %s\n", clientHash, claims.EATNonce[1])
		}

	} else {
		fmt.Printf("error unmarshalling jwt token %v\n", err)
		os.Exit(1)
	}

	// Now send the data over the same attested
	// we are still using the same TLS conn as above

	fmt.Println("========================== GettingSigning certificate /cert  ==========================")

	// get the server certificate

	ccc := getSigningCertRequest{
		CN: "foo",
	}
	certBody, err := json.Marshal(ccc)
	if err != nil {
		fmt.Printf("Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	ccr, err := client.Post(fmt.Sprintf("https://%s/cert", *host), "application/json", bytes.NewBuffer(certBody))
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}

	certResponseBody, err := io.ReadAll(ccr.Body)
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}
	// close now so we can reuse the same TLS conn
	err = ccr.Body.Close()
	if err != nil {
		fmt.Printf("Error closing body %v\n", err)
		os.Exit(1)
	}
	var getCertResp getSigningCertResponse
	err = json.Unmarshal(certResponseBody, &getCertResp)
	if err != nil {
		fmt.Printf("Error parsing response from TEE %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("                          Status: %s\n", cr.Status)

	// parse the instance certificate
	ccrt, err := base64.StdEncoding.DecodeString(getCertResp.Certificate)
	if err != nil {
		fmt.Printf("Error decoding instance certificate %v\n", err)
		os.Exit(1)
	}
	certPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ccrt,
		},
	)
	fmt.Printf("Instance Certificate: \n%s\n", certPEM)
	instanceCertificate, err := x509.ParseCertificate(ccrt)
	if err != nil {
		fmt.Printf("Error decoding instance certificate %v\n", err)
		os.Exit(1)
	}
	hasher := sha256.New()
	hasher.Write(instanceCertificate.Raw)
	instanceCertificateHash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))
	fmt.Printf("                          server Certificate Hash %s\n", instanceCertificateHash)

	token, err = jwt.ParseWithClaims(getCertResp.AttestationJWT, gcpIdentityDoc, func(token *jwt.Token) (interface{}, error) {
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
		fmt.Printf("Error parsing  JWT %v\n", err)
		os.Exit(1)
	}

	if claims, ok := token.Claims.(*csclaims.Claims); ok && token.Valid {
		fmt.Println("Attestation Claims: ")
		printedClaims, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			fmt.Printf("Error parsing token %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(printedClaims))

		for _, a := range claims.Audience {
			if a == base64.StdEncoding.EncodeToString(clientCertHash.Sum(nil)) {
				fmt.Printf("                          Audience value matches client cert hash %s  \n", a)
			}
		}

		if *expected_image_hash != claims.Submods.Container.ImageReference {
			fmt.Printf("unexpected image hash.  Expected %s,  got %s\n", *expected_image_hash, claims.Submods.Container.ImageReference)
			os.Exit(1)
		}

		// just by this repo's convention,
		// claims.EATNonce[0] is the has of the server certificate's public key

		if len(claims.EATNonce) != 1 {
			fmt.Printf("Expected eat nonce to have one value, got %d\n", len(claims.EATNonce))
			os.Exit(1)
		}

		if instanceCertificateHash != claims.EATNonce[0] {
			fmt.Printf("Hash of instance certificate mismatched, expected %s, got %s\n", instanceCertificateHash, claims.EATNonce[0])
			os.Exit(1)
		} else {
			fmt.Printf("                          Instance certificate hash matches expected eat_nonce[0]=%s, got %s\n", instanceCertificateHash, claims.EATNonce[0])
		}

		// to double check the cert is legit or not (for whatever reason),  verify a sample test signature
		signature, err := base64.StdEncoding.DecodeString(getCertResp.Signature)
		if err != nil {
			fmt.Printf("Error decoding test signature %v\n", err)
			os.Exit(1)
		}

		th := sha256.New()
		th.Write([]byte(getCertResp.SignedData))

		err = rsa.VerifyPKCS1v15(instanceCertificate.PublicKey.(*rsa.PublicKey), crypto.SHA256, th.Sum(nil), signature)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error verifying test signature: %s\n", err)
			return
		}
		fmt.Printf("                          Test signature verified\n")

	} else {
		fmt.Printf("error unmarshalling jwt token %v\n", err)
		os.Exit(1)
	}

	// now increment
	fmt.Println("========================== Increment /increment  ==========================")

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
	p := incrementRequest{
		Key:           *kmsKey,
		Audience:      *audience,
		EncryptedData: e,
	}
	body, err := json.Marshal(p)
	if err != nil {
		fmt.Printf("Error marshalling POST JSON %v\n", err)
		os.Exit(1)
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/increment", *host), "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error posting to TEE %v\n", err)
		os.Exit(1)
	}

	var pr incrementResponse
	err = json.Unmarshal(body, &pr)
	if err != nil {
		fmt.Printf("Error parsing response from TEE %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("                          Status: %s\n", resp.Status)
	fmt.Printf("                          Count: %v\n", pr.Count)
}
