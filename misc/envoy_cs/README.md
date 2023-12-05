### Confidential Space Attestation JWT validation with Envoy

Simple envoy JWT and LUA filters which validate a confidential space JWT for a couple of other claims.

You can use this to decode the attestation JWT emitted from inside confidential space _to_ an external service

The basic flow here is trivial:

`confidential_space (attestation-token)` --> `envoy running somewhere else (validate JWT)` --> `httpbin (or just respond back to conf_space)` 

The idea is you would host the envoy filter on some system outside of conf_space and would respond back with some data after validation (vs in this example calling httpbin)

To use, download envoy and run

```bash
./envoy -c envoy-conf-jwt.yaml -l debug
```

Using a sample JWT token here which pretends to be the attestation JWT (the fake attestation oidc is its taken from: [DIY OIDC Server](https://github.com/salrashid123/diy_oidc))


```bash
export TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYUtleUlEXzEiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL3NvbWVfYXVkaWVuY2UiLCJkYmdzdGF0IjoiZGlzYWJsZWQtc2luY2UtYm9vdCIsImVhdF9ub25jZSI6WyJLSzgtQ1RoZV9XOWkwRldUWDdMLURNYnZzdUN2djVLMTBtNmZXSk8tLU1BIiwib3RoZXJub25jZSJdLCJleHAiOjE3MzM4OTM4MDksImdvb2dsZV9zZXJ2aWNlX2FjY291bnRzIjpbIm9wZXJhdG9yLXN2Yy1hY2NvdW50QHZlZ2FzLWNvZGVsYWItNS5pYW0uZ3NlcnZpY2VhY2NvdW50LmNvbSJdLCJod21vZGVsIjoiR0NQX0FNRF9TRVYiLCJpYXQiOjE2OTc4OTM4MDksImlzcyI6Imh0dHBzOi8vaWRwLW9uLWNsb3VkLXJ1bi0za2RlenJ1enVhLXVjLmEucnVuLmFwcCIsIm5hbWUiOiJhbGljZSIsIm5iZiI6MTY5Nzg5MzgwOSwib2VtaWQiOjExMTI5LCJzZWNib290Ijp0cnVlLCJzdWIiOiJhbGljZUBkb21haW4uY29tIiwic3VibW9kcyI6eyJjb25maWRlbnRpYWxfc3BhY2UiOnsic3VwcG9ydF9hdHRyaWJ1dGVzIjpbIkxBVEVTVCIsIlNUQUJMRSIsIlVTQUJMRSJdfSwiY29udGFpbmVyIjp7ImFyZ3MiOlsiLi9zZXJ2ZXIiXSwiY21kX292ZXJyaWRlIjpudWxsLCJlbnYiOnsiSE9TVE5BTUUiOiJ2bTEiLCJQQVRIIjoiL3Vzci9sb2NhbC9zYmluOi91c3IvbG9jYWwvYmluOi91c3Ivc2JpbjovdXNyL2Jpbjovc2JpbjovYmluIiwiU1NMX0NFUlRfRklMRSI6Ii9ldGMvc3NsL2NlcnRzL2NhLWNlcnRpZmljYXRlcy5jcnQifSwiZW52X292ZXJyaWRlIjpudWxsLCJpbWFnZV9kaWdlc3QiOiJzaGEyNTY6YTc2ZmQ0MGQ4NTFkODk1ZjZlZWUyYjA0N2NlYWY4NGZjYjA2ODEyZWYxNzA3ZGJjOWEyMmU0ZTc0ZjRjZmQxZiIsImltYWdlX2lkIjoic2hhMjU2OmVhOTAxZTI5ZGU4MjM5N2I3ODYxNmZiOThjYjdkNWQwOWFmZWIxMWI4MDRhYzk4ZGFiY2Q3NzIwOGU3OWVhNDEiLCJpbWFnZV9yZWZlcmVuY2UiOiJ1cy1jZW50cmFsMS1kb2NrZXIucGtnLmRldi9taW5lcmFsLW1pbnV0aWEtODIwL3JlcG8xL3RlZUBzaGEyNTY6YTc2ZmQ0MGQ4NTFkODk1ZjZlZWUyYjA0N2NlYWY4NGZjYjA2ODEyZWYxNzA3ZGJjOWEyMmU0ZTc0ZjRjZmQxZiIsInJlc3RhcnRfcG9saWN5IjoiTmV2ZXIifSwiZ2NlIjp7Imluc3RhbmNlX2lkIjoiNjkyMDg2NzM3NTcxMjg2MTgyMyIsImluc3RhbmNlX25hbWUiOiJ2bTEiLCJwcm9qZWN0X2lkIjoidmVnYXMtY29kZWxhYi01IiwicHJvamVjdF9udW1iZXIiOiI3NTQ1NzUyMTc0NSIsInpvbmUiOiJ1cy1jZW50cmFsMS1hIn19LCJzd25hbWUiOiJDT05GSURFTlRJQUxfU1BBQ0UiLCJzd3ZlcnNpb24iOlsiMSJdLCJ0ZWUiOnsiY29udGFpbmVyIjp7ImFyZ3MiOm51bGwsImNtZF9vdmVycmlkZSI6bnVsbCwiZW52IjpudWxsLCJlbnZfb3ZlcnJpZGUiOm51bGwsImltYWdlX2RpZ2VzdCI6IiIsImltYWdlX2lkIjoiIiwiaW1hZ2VfcmVmZXJlbmNlIjoiIiwicmVzdGFydF9wb2xpY3kiOiIifSwiZ2NlIjp7fSwicGxhdGZvcm0iOnt9LCJ2ZXJzaW9uIjp7Im1ham9yIjowLCJtaW5vciI6MH19fQ.AWVd0rIsQjLpmu0R2JdFAEFcNWakU9X86OF5m-J8q56Bz40H81TfB506gO947OHpHwSvcYMNzCWqgHtOZcl8cLTVXww1Ea1CW2K8jqbXlFDpYTzxWh5umafJ4tdyYClNmJeJnAifk5C1u3ZJjy0PizsbjKuPpj8QrVG5BUYB2gpx8xUV76jaqszK0Q853DeMIsZBnBwqLelKmAnW3hG-9nCqx3D5xCBEj2ty9fZuUe1fhQ20MxRI7CebQOTXwM4VINDM2PdFPsuJogSNFIwI9_-CBNDEt_7l3rQpmdg8IZEWu3LScrJOVVIvxfsjFiJL6_94wk_UZMs4GE4yee3jYQ"

curl -v -H "host: http.domain.com" --cacert certs/http-server-tls-ca-chain.crt \
   --resolve  http.domain.com:8080:127.0.0.1 -H "Authorization: Bearer $TOKEN" https://http.domain.com:8080/get
```

---

### Attestation JWT as Certificate Bound Token

This is more complex and unusual application where confidential space retruns a certificate bound attestation token to a client and the client then presents that same token to some other service.

Basically its a type of

* [Envoy Certificate Bound Token](https://github.com/salrashid123/envoy_cert_bound_token)

where there are two steps:

- 1. `client (mtls)` --> `confidential_space` --> `[validate cert; return attestation_token(eat_nonce=client_hash)]`

- 2. `client (mtls + attestation-token)` --> `envoy (validate JWT; client_hash matches eat_nonce)` --> `httpbin` 


In this example the client certificate has the following hash value which is encoded into the test JWT within the `eat_nonce` claim.

```bash
openssl x509 -in ../../http_client/certs/client-collaborator1.crt -outform DER | openssl dgst -sha256 | cut -d" " -f2
28af3e09385efd6f62d055935fb2fe0cc6efb2e0afbf92b5d26e9f5893bef8c0

echo "28af3e09385efd6f62d055935fb2fe0cc6efb2e0afbf92b5d26e9f5893bef8c0" | xxd -r -p - | openssl enc -a | tr -d '=' | tr '/+' '_-'
KK8-CThe_W9i0FWTX7L-DMbvsuCvv5K10m6fWJO--MA
```

CS would return this attestation token back to the client after verifying its peer certificate hash value into the eat_nonce(eg `/connect`)

```golang
func connectHandler(w http.ResponseWriter, r *http.Request) {
	val := r.Context().Value(contextKey("event")).(event)
	var clientCertHash string
	// note val.PeerCertificates[0] is the leaf
	for _, c := range val.PeerCertificates {
		h := sha256.New()
		h.Write(c.Raw)
		clientCertHash = base64.StdEncoding.EncodeToString(h.Sum(nil))
	}
	var post connectRequest
	err := json.NewDecoder(r.Body).Decode(&post)

	customTokenValue, err := getCustomAttestation(customToken{
		Audience: clientCertHash,
		Nonces:   []string{val.EKM, clientCertHash},
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&connectResponse{
		Uid:            post.Uid,
		AttestationJWT: customTokenValue,
	})
}
```

the Attestation JWT is formatted as shown below


The client can then present the JWT to envoy somewhere else and envoy will 

1. confirm the JWT claims are valid
2. the TLS peer does infact have the client certificate in posession 

(i.,e the token is bound to the cert)


To use,

```bash
./envoy -c envoy-conf-cert-bound.yaml -l debug

curl -v -H "host: http.domain.com" --cacert certs/http-server-tls-ca-chain.crt \
    --cert ../../http_client/certs/client-collaborator1.crt --key ../../http_client/certs/client-collaborator1.key \
    --resolve  http.domain.com:8080:127.0.0.1 -H "Authorization: Bearer $TOKEN" https://http.domain.com:8080/get
```

---

```json
{
  "alg": "RS256",
  "kid": "rsaKeyID_1",
  "typ": "JWT"
}
{
  "aud": "https://some_audience",
  "dbgstat": "disabled-since-boot",
  "eat_nonce": [
    "KK8-CThe_W9i0FWTX7L-DMbvsuCvv5K10m6fWJO--MA",
    "othernonce"
  ],
  "exp": 1733893809,
  "google_service_accounts": [
    "operator-svc-account@vegas-codelab-5.iam.gserviceaccount.com"
  ],
  "hwmodel": "GCP_AMD_SEV",
  "iat": 1697893809,
  "iss": "https://idp-on-cloud-run-3kdezruzua-uc.a.run.app",
  "name": "alice",
  "nbf": 1697893809,
  "oemid": 11129,
  "secboot": true,
  "sub": "alice@domain.com",
  "submods": {
    "confidential_space": {
      "support_attributes": [
        "LATEST",
        "STABLE",
        "USABLE"
      ]
    },
    "container": {
      "args": [
        "./server"
      ],
      "cmd_override": null,
      "env": {
        "HOSTNAME": "vm1",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"
      },
      "env_override": null,
      "image_digest": "sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f",
      "image_id": "sha256:ea901e29de82397b78616fb98cb7d5d09afeb11b804ac98dabcd77208e79ea41",
      "image_reference": "us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f",
      "restart_policy": "Never"
    },
    "gce": {
      "instance_id": "6920867375712861823",
      "instance_name": "vm1",
      "project_id": "vegas-codelab-5",
      "project_number": "75457521745",
      "zone": "us-central1-a"
    }
  },
  "swname": "CONFIDENTIAL_SPACE",
  "swversion": [
    "1"
  ],
  "tee": {
    "container": {
      "args": null,
      "cmd_override": null,
      "env": null,
      "env_override": null,
      "image_digest": "",
      "image_id": "",
      "image_reference": "",
      "restart_policy": ""
    },
    "gce": {},
    "platform": {},
    "version": {
      "major": 0,
      "minor": 0
    }
  }
}
```

---

### Other references

* [Envoy mTLS](https://github.com/salrashid123/envoy_mtls)
* [Envoy External Processing Filter](https://github.com/salrashid123/envoy_ext_proc)
* [Envoy RBAC](https://github.com/salrashid123/envoy_rbac)
* [Envoy External Authorization](https://github.com/salrashid123/envoy_external_authz)
* [Envoy IAP](https://github.com/salrashid123/envoy_iap)
