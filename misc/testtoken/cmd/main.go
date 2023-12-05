package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	//"github.com/gorilla/mux"
	csclaims "github.com/salrashid123/confidential_space/claims"
	tk "github.com/salrashid123/confidential_space/misc/testtoken"
	//"golang.org/x/net/http2"
)

var (
// listen       = flag.Bool("listen", false, "listen on domain socket")
// domainSocket = flag.String("domainSocket", "/tmp/teeserver.sock", "domain socket")
)

func main() {

	flag.Parse()
	// create a custom token
	tts := &tk.CustomToken{
		Audience:  "https://myaudience",
		Nonces:    []string{"foo", "bar"},
		TokenType: tk.TOKEN_TYPE_OIDC,
	}
	customTokenValue, err := tk.GetCustomAttestation(tts)
	if err != nil {
		fmt.Printf(" Error creating Custom JWT %v", err)
		os.Exit(1)
	}
	fmt.Printf("CustomToken:  %s\n", customTokenValue)

	// verify it
	dec, err := tk.VerifyToken(customTokenValue)
	if err != nil {
		fmt.Printf(" Error decoding token %v", err)
		os.Exit(1)
	}

	fmt.Printf("Verified: %t\n", dec.Valid)

	// or for full control of all the claims,

	now := time.Now()
	expAt := time.Now().Add(time.Hour)
	cclaims := csclaims.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
			Audience:  jwt.ClaimStrings{"https://some_audience"},
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
		EATNonce:              []string{"foo", "bar"},
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
	}

	fullTokenValue, err := tk.GetAttestation(cclaims)
	if err != nil {
		fmt.Printf(" Error creating full JWT %v", err)
		os.Exit(1)
	}
	fmt.Printf("Full JWT %s\n", fullTokenValue)

	/// optionally start socket listener

	/*
				curl -v -H 'Content-Type: application/json' \
		            -d '{"audience":"https://httpbin.org", "nonces": ["0000000000000000000","0000000000000000001"], "token_type": "OIDC"}' \
					 --unix-socket /tmp/teeserver.sock  http://localhost/v1/token

	*/
	// 	if *listen {
	// 		var l net.Listener
	// 		var err error
	// 		ctx := context.Background()
	// 		l, err = net.Listen("unix", *domainSocket)
	// 		if err != nil {
	// 			fmt.Printf("Error listening to domain socket: %v\n", err)
	// 			os.Exit(-1)
	// 		}
	// 		defer l.Close()
	// 		r := mux.NewRouter()
	// 		r.Handle("/v1/token", http.HandlerFunc(tokenHandler)).Methods(http.MethodPost)
	// 		http.Handle("/", r)
	// 		srv := &http.Server{}
	// 		http2.ConfigureServer(srv, &http2.Server{})
	// 		done := make(chan os.Signal, 1)
	// 		signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	// 		go func() {
	// 			if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
	// 				fmt.Printf("listen: %s\n", err)
	// 				os.Exit(1)
	// 			}
	// 		}()
	// 		fmt.Printf("Server Started")
	// 		<-done
	// 		fmt.Printf("Server Stopped")
	//		if err := srv.Shutdown(ctx); err != nil {
	//			fmt.Printf("Server Shutdown Failed:%+v", err)
	//			os.Exit(1)
	//		}
	//	}
}

// func tokenHandler(w http.ResponseWriter, r *http.Request) {
// 	p := &tk.CustomToken{}
// 	// Try to decode the request body into the struct. If there is an error,
// 	// respond to the client with the error message and a 400 status code.
// 	err := json.NewDecoder(r.Body).Decode(&p)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	customTokenValue, err := tk.GetCustomAttestation(p)
// 	if err != nil {
// 		fmt.Printf(" Error creating Custom JWT %v", err)
// 		os.Exit(1)
// 	}
// 	fmt.Printf("CustomToken:  %s\n", customTokenValue)
// 	w.Header().Set("Content-Type", "text/plain")
// 	fmt.Fprint(w, customTokenValue)
// }
