package signature

import data.signature.verified

default allow = false

allow {
    input.predicateType == "https://cosign.sigstore.dev/attestation/v1"

    predicates := json.unmarshal(input.predicate.Data)
    predicates.foo == "bar"
}