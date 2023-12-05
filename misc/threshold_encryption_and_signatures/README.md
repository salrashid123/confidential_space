#### Threshold Encryption and Signatures

You can also easily use the TEE to perform [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem) functions like signing or encryption/decryption.

In this mode, each collaborator's threshold key is encrypted by their own KMS key and is decrypted within the TEE.

Once the TEE receives the `t of n` keys, it can perform encryption or signing per key-type.

The following uses [go.dedis.ch/kyber](https://pkg.go.dev/go.dedis.ch/kyber) library and writes the public and private keys in binary to a file.  

For use with KMS, each participant would encrypt the binary form of the marshalled key first and transmit that content to the TEE for decryption.

* [Threshold Signatures](https://gist.github.com/salrashid123/c936fcbaa40c403232351f67c17ee12f)
* [Threshold Encryption](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13)



### AES/RSA Derived key Encryption and Persistence

In a multiparty system, each collaborator may release a partial key which when combined would allow encryption at rest on GCS or allow for decryption in bigquery.

What this allows is for the operator to persist data into GCS in such a way that the data can only be sealed if all or some threshold of collaborators combine keys.

For example if alice and bob release a key to the TEE, the TEE can use that to persist data in GCS by a CSEK key which is derived from both parts

* [GCS Customer Supplied Encryption Key](https://cloud.google.com/docs/security/encryption/customer-supplied-encryption-keys#cloud_storage)

The net effect is the object in GCS is sealed in such a way that both alice and bob need to coordinate to read the object (which would presumably be done in another TEE)

Similarly, both partial keys can be used to generate any arbitrary AES key Tink Key or even RSA keypair

* [Simple Examples of using Tink Encryption library in Golang](https://github.com/salrashid123/tink_samples)

  - [AES SIV](https://github.com/salrashid123/tink_samples/blob/main/client_siv/main.go#L30)
  - [AES GCM](https://github.com/salrashid123/tink_samples/blob/main/external_aes_gcm/main.go#L49)
  - [Deterministic RSA Key](https://github.com/salrashid123/mcbn#deterministic-rsa-key)


### Using Threshold Key as CSEK

Finally, if you want to save a file to GCS such that t of n participants need to collude to decrypt and read contents, a TEE can save a file using the threshold key while specifying a [Customer Supplied Encryption Key (CSEK)](https://cloud.google.com/docs/security/encryption/customer-supplied-encryption-keys#cloud_storage)