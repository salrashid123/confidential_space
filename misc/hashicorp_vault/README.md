#### Using Hashicorp Vault

If you have an on-prem [Hashicorp Vault](https://www.vaultproject.io/) which saves encryption keys, you can access it from within the TEE by passing through a GCP KMS encrypted `VAULT_TOKEN`, unwrapping it within the TEE.

Alternatively, you can just use Vault's [JWT Auth](https://developer.hashicorp.com/vault/docs/auth/jwt) mechansim.

In this mode, you use the TEE's attestation token and emit that to your vault server.  The vault server validates the TEE specicifcations and returns a `VAULT_TOKEN` for the TEE to use again.

>> Note: you _are_ emitting the TEE's attestation token externally here which means you must issue a custom JWT token intended for vault

Critically, also note that the TEE attestation token has a fixed audience value (`https://sts.googleapis.com`).  If you sent this TEE token to your vault server as-is, you are somewhat misusing the intent for that claim and token (i.,e its intended auidence is GCP's STS server; not your vault server). 

Once Confidential Space allows custom audiences,  you can use this VAULT auth mechansim against multiple collaborators onprem server as well as GCP APIs since you can define your own audience settings.

In short, its not recommened to use this mechanism but the following is there for completeness:

Anyway, here is a sample Vault JWT configuration that would authorize a specific image but requires a custom audience (`https://your.vault.audience`)

```hcl
vault write auth/jwt/config \
    jwks_url="https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com" \
    bound_issuer="https://confidentialcomputing.googleapis.com/"
```

Vault operator defines fine-grained role that enforces the image policy

```hcl
vault write auth/jwt/role/my-jwt-role -<<EOF
{
  "role_type": "jwt",
  "policies": ["token-policy","secrets-policy"],
  "token_explicit_max_ttl": 60,
  "user_claim": "sub",
  "bound_audiences": ["https://your.vault.audience"],
  "bound_subject": "https://www.googleapis.com/compute/v1/projects/vegas-codelab-5/zones/us-central1-a/instances/vm1",
  "claims_mappings": {
    "hwmodel": "hwmodel",
    "swname": "swname",
    "/submods/confidential_space/support_attributes": "/submods/confidential_space/support_attributes",    
    "/submods/container/image_digest": "/submods/container/image_digest",
    "/submods/gce/project_id":"/submods/gce/project_id",
    "google_service_accounts":"google_service_accounts"
  },
  "bound_claims": {
    "hwmodel": "GCP_AMD_SEV",
    "swname": "CONFIDENTIAL_SPACE",
    "/submods/confidential_space/support_attributes": ["STABLE"],
    "/submods/container/image_digest": ["sha256:1447781b9a6fd0a09a6352c10efaffaf6a67d2d12940b56d00cb38c5b56ad646 "],
    "/submods/gce/project_id": ["$OPERATOR_PROJECT_ID"],
    "google_service_accounts":["operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com"]
  }  
}
EOF
```

Exchange TEE Attestation token for an on-prem `VAULT_TOKEN`:

The equivalent usage with vault cli:

```bash
export VAULT_CACERT='/path/to/tls/ca.pem'
export VAULT_ADDR='https://your_vault_server:443'

export JWT_TOKEN=`cat /run/container_launcher/attestation_verifier_claims_token`

export VAULT_TOKEN=`vault write -field="token" auth/jwt/login role=my-jwt-role jwt="$JWT_TOKEN"`
echo $VAULT_TOKEN

# now use the vault token to access a secret or key
vault kv put kv/message foo=world
vault kv get kv/message
```

also see

- [Vault auth and secrets on GCP](https://github.com/salrashid123/vault_gcp)
