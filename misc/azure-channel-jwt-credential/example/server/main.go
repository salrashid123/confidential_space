package main

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat/go-jwx/jwk"

	"github.com/gorilla/mux"
	azsigner "github.com/salrashid123/azsigner"
	salpem "github.com/salrashid123/signer/pem"
	"golang.org/x/net/http2"

	csclaims "github.com/salrashid123/confidential_space/claims"
)

var (
	clientCertRootCA = flag.String("clientCertRootCA", "certs/tls-ca-chain.pem", "Root CA of the client cert")
	serverCert       = flag.String("serverCert", "certs/server.crt", "Server Certificate to use")
	serverKey        = flag.String("serverKey", "certs/server.key", "Server cert key")
	audience         = flag.String("audienct", "https://server.domain.com", "JWT Audience Claim to check")

	useCert      = flag.Bool("useCert", true, "use cred x509")
	azurePublic  = flag.String("azurePublic", "", "Azure cred public cert")
	azurePrivate = flag.String("azurePrivate", "", "Azure cred private key")

	azureTenant = flag.String("azureTenant", "", "Azure TenantID")
	azureAppID  = flag.String("azureAppID", "", "Azure AppID")
	azureSecret = flag.String("azureSecret", "", "Azure Secret")

	scope  = flag.String("scope", "", "Allowed Azure Scope") // either set statically or allow clients to specify; this repo allows the client to set scopes
	jwtSet *jwk.Set

	cert    *x509.Certificate
	ksigner crypto.Signer
)

type tokenPayload struct {
	jwt.RegisteredClaims
	Tenant string `json:"tenant,omitempty"` // optionally allow the client to specify the tenant and appid, this is currently ignored in this implementation
	AppID  string `json:"appid,omitempty"`
	Scope  string `json:"scope"` // allow client to specify
}

type tokenRequest struct {
	TokenJWT       string `json:"token_jwt"`
	AttestationJWT string `json:"attestation_jwt"`
}

type rpctokenResponse struct {
	ExpiresOn   string `json:"expires_in"`
	AccessToken string `json:"access_token"`
}

type apiTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	ExtExpiresIn int64  `json:"ext_expires_in,omitempty"`
}

const (
	//jwksURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	jwksURL = "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs"
	RFC3339 = "2006-01-02T15:04:05Z07:00"
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

	// optionally check if tokp.Scope is an allowed scope to request a token for
	// this example simply uses any scope provided by the client

	// **************************
	if *useCert {
		cred, err := azsigner.NewSignerCredentials(
			*azureTenant,
			*azureAppID,
			[]*x509.Certificate{cert},
			ksigner, nil)

		if err != nil {
			log.Printf("Error getting azsigner %v\n", err)
			http.Error(w, "Error getting azsigner %v\n", http.StatusBadRequest)
			return
		}
		tk, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{
			Scopes: []string{tokp.Scope},
		})
		if err != nil {
			log.Printf("Error getting token 1 %v\n", err)
			http.Error(w, fmt.Sprintf("Error getting token %v\n", err), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(&rpctokenResponse{
			AccessToken: tk.Token,
			ExpiresOn:   tk.ExpiresOn.Format(RFC3339),
		})
	} else {
		if tokp.Scope == "" {
			fmt.Println("scope cannot be nil")
			http.Error(w, "Error: scope cannot be nil  %v\n", http.StatusBadRequest)
			return
		}
		u := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", *azureTenant) // to use the token submitted by the client tokp.Tenant
		form := url.Values{}

		form.Add("grant_type", "client_credentials")
		form.Add("client_id", *azureAppID)
		form.Add("client_secret", *azureSecret)
		form.Add("scope", tokp.Scope)

		azSTSResp, err := http.PostForm(u, form)
		if err != nil {
			log.Printf("Error getting token3  %v\n", err)
			http.Error(w, "Error getting token %v\n", http.StatusBadRequest)
			return
		}

		if azSTSResp.StatusCode != http.StatusOK {
			log.Printf("Error response  %v\n", err)
			http.Error(w, "Error response%v\n", http.StatusBadRequest)
			return
		}
		defer azSTSResp.Body.Close()
		if azSTSResp.StatusCode != http.StatusOK {
			bodyBytes, err := io.ReadAll(azSTSResp.Body)
			if err != nil {
				log.Printf("Error response  %v\n", err)
				http.Error(w, "Error response%v\n", http.StatusBadRequest)
				return
			}
			log.Printf("Unable to exchange token %s,  %v", string(bodyBytes), err)
			http.Error(w, "Error getting token 4 %v\n", http.StatusBadRequest)
			return
		}

		tresp := &apiTokenResponse{}
		err = json.NewDecoder(azSTSResp.Body).Decode(tresp)
		if err != nil {
			http.Error(w, "nable to unmarshal azure token %v\n", http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(&rpctokenResponse{
			AccessToken: tresp.AccessToken,
			ExpiresOn:   time.Now().UTC().Add(time.Second * time.Duration(tresp.ExpiresIn)).Format(RFC3339),
		})
	}

	w.Header().Set("Content-Type", "application/json")

	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()

	if *useCert && (*azurePublic == "" || *azurePrivate == "") {
		log.Println("Error Please specify azurePublic and azurePrivate if useCert is set")
		os.Exit(1)
	}

	var err error

	if *useCert {
		ksigner, err = salpem.NewPEMCrypto(&salpem.PEM{
			PrivatePEMFile: *azurePrivate,
		})
		if err != nil {
			fmt.Printf("Error initializing private key: " + err.Error())
			os.Exit(1)
		}

		localhostCert, err := os.ReadFile(*azurePublic)
		if err != nil {
			fmt.Printf("Error reading certificate: " + err.Error())
			os.Exit(1)
		}
		pubBlock, _ := pem.Decode([]byte(localhostCert))
		cert, err = x509.ParseCertificate(pubBlock.Bytes)
		if err != nil {
			fmt.Printf("Error loading certificate: " + err.Error())
			os.Exit(1)
		}
	}

	jwt.MarshalSingleStringAsArray = false

	// now load the server certs

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
