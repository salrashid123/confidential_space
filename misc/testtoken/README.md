#### Generate Confidential Space Test Tokens

This repo also contains a sample jwt generator which creates a fake confidential space custom attestation token.

Use this to test/verify the claims provided by the process credential or provider locally.


The fake oidc server is from [DIY OIDC Server](ttps://github.com/salrashid123/diy_oidc)

```bash
curl -s https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/.well-known/openid-configuration |jq '.'

{
  "issuer": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
  "jwks_uri": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app/certs",
  "id_token_signing_alg_values_supported": [
    "RS256",
    "ES256",
    "HS256"
  ],
  "response_types_supported": [
    "id_token"
  ],
  "subject_types_supported": [
    "public"
  ]
}
```

to create and verify a fake jwt,

```golang
package main

import (
	"fmt"
	"log"
	"os"

	tk "github.com/salrashid123/confidential_space/misc/testtoken"
)

func main() {
	fmt.Println("starting")
	tts := &tk.CustomToken{
		Audience: "https://myaudience",
		Nonces:   []string{"foo", "bar"},
		TokenType: tk.TOKEN_TYPE_OIDC,			
	}
	customTokenValue, err := tk.GetCustomAttestation(tts)
	if err != nil {
		log.Printf(" Error creating Custom JWT %v", err)
		os.Exit(1)
	}
	fmt.Printf("CustomToken:  %s", customTokenValue)
	dec, err := tk.VerifyToken(customTokenValue)
	if err != nil {
		log.Printf(" Error decoding token %v", err)
		os.Exit(1)
	}

	fmt.Printf("%v\n", dec.Claims)
}
```

If you want to customize the attestation_jwt, just supply the full struct in `GetAttestation(csclaims csclaims.Claims)`

see sample in

```bash
go run cmd/main.go
```


---

For bazel,

```bash
docker run   -e USER="$(id -u)" \
  -v `pwd`:/src/workspace   -v /tmp/build_output:/tmp/build_output \
   -v /var/run/docker.sock:/var/run/docker.sock   -w /src/workspace  \
   gcr.io/cloud-builders/bazel@sha256:f00a985c3196cc58819b6f7e8e40353273bc20e8f24b54d9c92d5279bb5b3fad \
    --output_user_root=/tmp/build_output   run :gazelle -- update-repos -from_file=go.mod -prune=true -to_macro=repositories.bzl%go_repositories

docker run   -e USER="$(id -u)" \
  -v `pwd`:/src/workspace   -v /tmp/build_output:/tmp/build_output \
   -v /var/run/docker.sock:/var/run/docker.sock   -w /src/workspace  \
   gcr.io/cloud-builders/bazel@sha256:f00a985c3196cc58819b6f7e8e40353273bc20e8f24b54d9c92d5279bb5b3fad \
    --output_user_root=/tmp/build_output   run  --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 //cmd:main
```