## Constructing Trusted Execution Environment (TEE) with GCP Confidential Space 

Tutorial on setting up [Google Cloud Confidential Space](https://cloud.google.com/blog/products/identity-security/announcing-confidential-space) (a `Trusted Execution Environments` (TEE)) for Untrusted Multiparty Compute (de-privileged data processing)

What this demonstrates is _one  way_ you can setup a GCP environment into which different organizations or companies can share data without worrying if the operator of that environment or any other collaborator can have direct access to the raw data.

Within the TEE, a Confidential Space VM can perform arbitrary data processing on each collaborator's data and output the appropriate result.

This specific demo accepts two collaborator's KMS encrypted data into the TEE and only within the TEE can the data get decrypted. Each collaborator is in charge of where and what security context their KMS key can be accessed and used (i.e., from only within this trusted, isolated environment).

---

Cast of characters:

* `Builder`:  
   - This project builds the trusted container image from source and optionally signs it using [cosign](https://github.com/sigstore/cosign).
   - Each collaborator may have access to inspect the code and build pipeline to confirm image code quality and image hash.
   - Each collaborator may build an image from source to cross check the hash value.  Images are built with `bazel` or `kaniko` and each will arrive at their own consistent same image hash.

* `Operator`
  - This project runs the trusted execution environment (`TEE`) where the image the builder provides runs.
  - An administrator for the operator's project cannot access the TEE (eg ssh into or alter the TEE at runtime)
  - TEE environment will use Confidential Space attestations (an `OIDC` token) to prove a specific image is running in a specific TEE.
  - Confidential Space attestations are presented to collaborators to prove TEE's are running trusted code and only then can the TEEs gain access to collaborators KMS key for decryption of sensitive data.

* `Collaborator-1`
  - This project is a data provider that encrypted some data with a KMS key they own
  - The collaborator defines their own workload identity pools  which authorizes OIDC tokens/attestations from a specific operator in a specific project and which asserts Confidential Space claims.
  - Collaborator grants access to their KMS key to the application within the TEE once it presents an attestation token issued to the TEE and which identifies a specific image hash in a Confidential Space environment.
  - Each collaborators can optionally sign the image hash and provide the signature to the builder to attach to the registry via `cosign`.  This capability is not included in this tutorial but would potentially only allow deployment if both collaborators provided signatures.

* `Collaborator-2`
  - This project is a data provider that encrypted some data with a KMS key they own
  - The collaborator also defines their own workload identity pools  which authorizes OIDC tokens/attestations from a specific operator in a specific project and which asserts Confidential Space claims.
  - Collaborator grants access to their KMS key to the application within the TEE once it presents an attestation token issued to the TEE and which identifies a specific image hash in a Confidential Space environment.

At the end of this exercise, each collaborator will encrypt some data with their KMS key, submit that data to a pubsub topic which the TEEs subscribe to.  Once a TEE receives a message, it will use the corresponding collaborators KMS key to decrypt their data.   This sample application doesn't do anything with the decrypted data:  it just keeps a counter of how many times a unique string was sent by any collaborator (i.e., just counts words).

![images/conf_space.png](images/conf_space.png)

---

>> **Important** this sample and code is not supported by Google; use as an example for testing only.

---

* [Setup](#setup)
* [Builder](#builder)
* [Operator](#operator)
* [Collaborator 1](#collaborator-1)
* [Collaborator 2](#collaborator-2)
* [Deploy](#deploy)
* [Test](#test)
* [Appendix](#appendix)
  - [Audit Logging](#audit-logging)
  - [Logging](#logging)
  - [Reproducible Builds](#reproducible-builds)
  - [VPC-SC](#vpc-sc)
  - [mTLS using acquired Keys](#mtls-using-acquired-keys)
  - [Service Discovery and TEE-TEE traffic](#service-discovery-and-tee-tee-traffic)
  - [Attestation Token and JWT Bearer token](#attestation-token-and-jwt-bearer-token)
  - [Authenticating with other Cloud Providers](#authenticating-with-other-cloud-providers)
  - [Outbound traffic via NAT](#outbound-traffic-via-nat)
  - [Client-Side Encryption](#client-side-encryption)
  - [Using BigQuery](#using-bigquery)
  - [Using BigQuery ML](#using-bigquery-ml)  
  - [Using CloudSQL](#using-cloudsql)
  - [Using SecretManager](#using-secretmanager)
  - [Using WebAssembly to run Sensitive Container Code](#using-webassembly-to-run-sensitive-container-code)
  - [Running Sensitive Machine Learning Code](#running-sensitive-machine-learning-code)
  - [Using Hashicorp Vault](#using-hashicorp-vault)
  - [Service Discovery](#service-discovery)  
  - [Threshold Encryption and Signatures](#threshold-encryption-and-signatures)
  - [Container image signing and verification](#container-image-signing-and-verification)
  - [Check Cosign Signature and Attestation at Runtime](#check-cosign-signature-and-attestation-at-runtime)
  - [Software Bill of Materials](#software-bill-of-materials)
  - [CNCF Confidential Containers](#cncf-confidential-containers)
  - [Azure Confidential Containers](#azure-confidential-containers)  

---

### Setup

The setup here requires four GCP projects. (`YOUR_BUILDER_PROJECT_ID, YOUR_OPERATOR_PROJECT_ID, YOUR_COLLABORATOR_1_PROJECT_ID, YOUR_COLLABORATOR_2_PROJECT_ID`). They may or may not be in different organizations (in practice, these would be likely be in different organizations).

```bash
export GCLOUD_USER=`gcloud config get-value core/account`

## Configure the "Builder"
gcloud config configurations create builder
gcloud config set account builder@builder-domain.com
gcloud config set project YOUR_BUILDER_PROJECT_ID

gcloud config configurations activate builder
export BUILDER_PROJECT_ID=`gcloud config get-value core/project`
export BUILDER_PROJECT_NUMBER=`gcloud projects describe $BUILDER_PROJECT_ID --format='value(projectNumber)'`

## Configure the "Operator"
gcloud config configurations create operator
gcloud config set account operatior@operator-domain.com
gcloud config set project YOUR_OPERATOR_PROJECT_ID

gcloud config configurations activate operator
export OPERATOR_PROJECT_ID=`gcloud config get-value core/project`
export OPERATOR_PROJECT_NUMBER=`gcloud projects describe $OPERATOR_PROJECT_ID --format='value(projectNumber)'`

## Configure  "Collaborator-1"
gcloud config configurations create collaborator-1
gcloud config set account admin@collaborator1-domain.com
gcloud config set project YOUR_COLLABORATOR_1_PROJECT

gcloud config configurations activate collaborator-1
export COLLABORATOR_1_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_1_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_1_PROJECT_ID --format='value(projectNumber)'`

## Configure  "Collaborator-2"
gcloud config configurations create collaborator-2
gcloud config set account admin@collaborator2-domain.com
gcloud config set project YOUR_COLLABORATOR_2_PROJECT

gcloud config configurations activate collaborator-1
export COLLABORATOR_2_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_2_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_2_PROJECT_ID --format='value(projectNumber)'`

echo $BUILDER_PROJECT_ID
echo $OPERATOR_PROJECT_ID
echo $COLLABORATOR_1_PROJECT_ID
echo $COLLABORATOR_2_PROJECT_ID
```

### Builder

It is critical that each collaborator trusts the code that is built does what it's intended to do:  just process the data as it's intended to do; does not exfiltrate data; does not write unencrypted raw data to disk or serialize it externally...the list goes on.

One option to do this is if each collaborator can view the code that will ultimately get deployed into the TEE.  The code and container there adheres to specific constraints to _not_do the bad stuff cited above.  What each code does to meet those standards is out of the scope for this article.  What we will show here is how a given code will create the same container hash value (i.,e you know the code you trust is running in a given container)

The technique used in this example uses `kaniko` (default) or `bazel` to create reproducible container images.  By that, I mean for the same code base, these will generate an image with _the same image hash value_ no matter where it's built.  Using this capability, a collaborator can clone the source, generate a build and then inspect the resulting image hash value.  The collaborators can then authorize that image hash access to their KMS key.

You don't _have to_ use `bazel` or `kaniko` to build an image (you can just use the `Dockerfile` provided in this example).  However, if you don't use those, you'll get a different image hash though. 

In this example using `kaniko`, the code will always produce a hash of  (see [reproducible Builds](#reproducible-builds))

* `tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f`

For more info, see

- [Building deterministic Docker images with Bazel](https://blog.bazel.build/2015/07/28/docker_build.html)
- [Deterministic container hashes and container signing using Cosign, Kaniko and Google Cloud Build](https://github.com/salrashid123/cosign_kaniko_cloud_build)
- [Deterministic container hashes and container signing using Cosign, Bazel and Google Cloud Build](https://github.com/salrashid123/cosign_bazel_cloud_build)
- [Deterministic builds with go + bazel + grpc + docker](https://github.com/salrashid123/go-grpc-bazel-docker)
- [Deterministic builds with nodejs + bazel + docker](https://github.com/salrashid123/nodejs-bazel-docker)
- [Deterministic container images with c++ and GCP APIs using bazel.](https://github.com/salrashid123/cpp-bazel-docker)
- [Deterministic container images with python and GCP APIs using bazel](https://github.com/salrashid123/python-bazel-docker)
- [Deterministic container images with java and GCP APIs using bazel](https://github.com/salrashid123/java-bazel-docker)
- [Understanding workload identity federation](https://blog.salrashid.dev/articles/2021/understanding_workload_identity_federation/)

Anyway, to setup,

```bash
gcloud config configurations activate builder
export BUILDER_PROJECT_ID=`gcloud config get-value core/project`
export BUILDER_PROJECT_NUMBER=`gcloud projects describe $BUILDER_PROJECT_ID --format='value(projectNumber)'`
export GCLOUD_USER=`gcloud config get-value core/account`

# enable some services and create the artifact registry that will hold the image and cosign signature
gcloud services enable \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com cloudkms.googleapis.com \
    iam.googleapis.com sourcerepo.googleapis.com

gcloud artifacts repositories create repo1 --repository-format=docker --location=us-central1 

# create a service account which cloud build will run as
gcloud iam service-accounts create cosign 

# allow cloud build to write logs
gcloud projects add-iam-policy-binding $BUILDER_PROJECT_ID \
  --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com  \
  --role=roles/logging.logWriter

# allow cloud build to write the image to the registry
gcloud artifacts repositories add-iam-policy-binding repo1 \
    --location=us-central1  \
    --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/artifactregistry.writer

# allow cloud build to access the public KMS keys used for signing (used for cosign)
gcloud projects add-iam-policy-binding $BUILDER_PROJECT_ID \
  --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com  \
  --role=roles/cloudkms.viewer

## create the kms key which will sign the image
gcloud kms keyrings create cosignkr --location=global

gcloud kms keys create key1 --keyring=cosignkr \
 --location=global --purpose=asymmetric-signing \
 --default-algorithm=ec-sign-p256-sha256

gcloud kms keys list  --keyring=cosignkr --location=global

# allow cloud build access to use the key to sign
gcloud kms keys add-iam-policy-binding key1 \
    --keyring=cosignkr --location=global \
    --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/cloudkms.signer

# allow current gcloud and cloud build to view the public key, in this step, you can also allow each collaborator viewer access
gcloud kms keys add-iam-policy-binding key1 \
    --keyring=cosignkr --location=global \
    --member=user:$GCLOUD_USER  \
    --role=roles/cloudkms.publicKeyViewer

gcloud kms keys add-iam-policy-binding key1 \
    --keyring=cosignkr --location=global \
    --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/cloudkms.publicKeyViewer  

# create a temp bucket for cloud build and allow cloud build permissions to use it
gsutil mb gs://$BUILDER_PROJECT_ID\_cloudbuild
gsutil iam ch \
  serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com:objectAdmin \
  gs://$BUILDER_PROJECT_ID\_cloudbuild

### for Kaniko

# with local docker
# see appendix to setup credentials for artifact registry
# cd /app
# docker run    -v `pwd`:/workspace   -v $HOME/.docker/config_kaniko.json:/kaniko/.docker/config.json:ro  \
#              gcr.io/kaniko-project/executor@sha256:034f15e6fe235490e64a4173d02d0a41f61382450c314fffed9b8ca96dff66b2    \
#               --dockerfile=Dockerfile --reproducible \
#               --destination "us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee:server"     --context dir:///workspace/

## for cloud build
# cd /app
# gcloud beta builds submit --config=cloudbuild_kaniko.yaml

# to build via commit for kaniko
gcloud source repos create cosign-repo

gcloud projects add-iam-policy-binding $BUILDER_PROJECT_ID \
  --member=serviceAccount:cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com \
  --role=roles/source.reader

gcloud source repos clone cosign-repo
cd cosign-repo
cp -R ../app/* .

git add -A
git commit -m "add"
git push 

# create a manual trigger
gcloud beta builds triggers create manual --region=global \
   --name=cosign-trigger --build-config=cloudbuild_kaniko.yaml \
   --repo=https://source.developers.google.com/p/$BUILDER_PROJECT_ID/r/cosign-repo \
   --repo-type=CLOUD_SOURCE_REPOSITORIES --branch=main \
   --service-account=projects/$BUILDER_PROJECT_ID/serviceAccounts/cosign@$BUILDER_PROJECT_ID.iam.gserviceaccount.com 

# now trigger
gcloud beta builds triggers run cosign-trigger --branch=main

# skopeo inspect --format "{{.Name}}@{{.Digest}}"  docker://us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee:server

### for Bazel
# gcloud beta builds submit --config=cloudbuild_bazel.yaml

## for local Bazel
## if you want to modify the code, use bazel to regenerate the dependencies
# to acquire bazel go dependency references
# bazel version 5.3.1

# bazel run :gazelle -- update-repos -from_file=go.mod -prune=true -to_macro=repositories.bzl%go_repositories

# to build image locally with bazel
#    repository = "us-central1-docker.pkg.dev/builder-project/repo1/tee"
# bazel build --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 :server
# bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 :server

# or build with docker with bazel image itself (preferable since its more hermetic):
# docker run   -e USER="$(id -u)" \
#   -v `pwd`:/src/workspace   -v /tmp/build_output:/tmp/build_output  \
#    -v /var/run/docker.sock:/var/run/docker.sock   -w /src/workspace  \
#    gcr.io/cloud-builders/bazel@sha256:f00a985c3196cc58819b6f7e8e40353273bc20e8f24b54d9c92d5279bb5b3fad  \
#     --output_user_root=/tmp/build_output   run  --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 :server
#
# skopeo inspect --format "{{.Name}}@{{.Digest}}"  docker-daemon:us-central1-docker.pkg.dev/builder-project/repo1/tee:server


# pull the image.  you should see the exact same image hash
docker pull us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee:server
docker inspect us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee:server | jq -r '.[].RepoDigests[]'
docker inspect us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f

# docker pull docker.io/salrashid123/tee:server
# docker inspect docker.io/salrashid123/tee:server
```

The cloud build step should give this specific container hash

![images/build_hash.png](images/build_hash.png)

The cloud build steps also used a kms key to sign the images using [cosign](https://github.com/sigstore/cosign).

Using `cosign` is a completely optional step used to add verification signatures and claims to the image.  See appendix for more information.


### Operator

Once the image is built and each collaborator is in agreement that the code contained in image 

- `us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f` 

isn't going to do anything malicious like exfiltrate their precious data, they can authorize that container to run in `Confidential Space` managed by an Operator.

The operator in this case simply constructs and manages GCP resources such that a Confidential Space VM within their infra will run this attested container only.

The container will get authorization tokens from each collaborators's workload identity pool _after_ it proves specifics about itself like 

* "am i running in Confidential Space VM?"
* "what is the image hash i'm running as?"
* "what is the service account ID i'm running as?"
* "confirm no ssh access by anyone is possible on this container runtime"
 
and so on...basically the operator's vm will have an identity token asserting/confirming by claims set by Confidential Space.  The claims included are shown in the appendix and specify things that help answer some information about the workload.

Anyway, to get started

```bash
# switch to the operator
gcloud config configurations activate operator
export OPERATOR_PROJECT_ID=`gcloud config get-value core/project`
export OPERATOR_PROJECT_NUMBER=`gcloud projects describe $OPERATOR_PROJECT_ID --format='value(projectNumber)'`

# enable some services and create the artifact registry that will hold the image and cosign signature
gcloud services enable \
    compute.googleapis.com confidentialcomputing.googleapis.com pubsub.googleapis.com

# create a service account the confidential space VM's will run as
gcloud iam service-accounts create operator-svc-account

# allow these service accounts permission to write to logs
gcloud projects add-iam-policy-binding $OPERATOR_PROJECT_ID \
  --member=serviceAccount:operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com  \
  --role=roles/logging.logWriter
```

We now have to switch to the builder account because we need to authorize the operator's service account access to download the image

```bash
### switch to image builder and grant the operator access to the image
gcloud config configurations activate builder

gcloud artifacts repositories add-iam-policy-binding repo1 \
    --location=us-central1  \
    --member=serviceAccount:operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/artifactregistry.reader --project $BUILDER_PROJECT_ID

# switch back to the operator
gcloud config configurations activate operator

## create a nat gateway; we're doing this because we do _not_ want an external ip address for the 
### TEE...instead, any outbound networks access would go through a NAT gateway which we can control better
gcloud compute addresses create natip --region=us-central1 --project $OPERATOR_PROJECT_ID

gcloud compute networks create teenetwork --project  $OPERATOR_PROJECT_ID

gcloud compute routers create router \
    --network teenetwork \
    --region us-central1 --project $OPERATOR_PROJECT_ID

gcloud compute routers nats create nat-all \
  --router=router --region=us-central1 \
  --nat-external-ip-pool=natip  \
  --nat-all-subnet-ip-ranges \
  --project $OPERATOR_PROJECT_ID
```    

We're done with the operator for now.

### Collaborator 1

There can be N collaborators but for each, the flow is mirrored:

They will create their own workload identity pool (WIP) specifically authorizing specifications for an id_token originating from the Operator's Confidential Space project.

They will also authorize access to their KMS key to decrypt some data to only a request from a specific container hash in that pre-authorized Operator's project

> NOTE: It's important that the collaborators retain control of this authorization at every step

```bash
# switch to collaborator-1
gcloud config configurations activate collaborator-1
export COLLABORATOR_1_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_1_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_1_PROJECT_ID --format='value(projectNumber)'`
export COLLABORATOR_1_GCLOUD_USER=`gcloud config get-value core/account`

# enable some services
gcloud services enable \
    pubsub.googleapis.com \
    cloudkms.googleapis.com \
    iam.googleapis.com pubsub.googleapis.com

# create a pool
gcloud iam workload-identity-pools create trusted-workload-pool --location="global"

# create a pool that authorizes requests where the identity token was issued by "Confidential Space's" OIDC issuer https://confidentialcomputing.googleapis.com
##  and which asserts its running on a CONFIDENTIAL_SPACE in the operator's project using the operator's service account we setup earlier
# note the following allows the **production** conf-space image:   "STABLE" in assertion.submods.confidential_space.support_attributes 
#   also see https://cloud.google.com/compute/confidential-vm/docs/reference/cs-attestation-policies
gcloud iam workload-identity-pools providers create-oidc attestation-verifier \
    --location="global"     --workload-identity-pool="trusted-workload-pool"   \
      --issuer-uri="https://confidentialcomputing.googleapis.com/"     --allowed-audiences="https://sts.googleapis.com" \
          --attribute-mapping="google.subject=assertion.sub,attribute.image_reference=assertion.submods.container.image_reference"  \
             --attribute-condition="assertion.swname=='CONFIDENTIAL_SPACE' && \"STABLE\" in assertion.submods.confidential_space.support_attributes && assertion.submods.gce.project_id=='$OPERATOR_PROJECT_ID' && 'operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com' in assertion.google_service_accounts"

# create a kms key and keyring
gcloud kms keyrings create kr1 --location=global --project $COLLABORATOR_1_PROJECT_ID
gcloud kms keys create --keyring=kr1 --location=global --purpose=encryption  key1

# allow current user to encrypt so that we can test
gcloud kms keys add-iam-policy-binding key1        --keyring=kr1 --location=global --project $COLLABORATOR_1_PROJECT_ID    \
     --member="user:$COLLABORATOR_1_GCLOUD_USER"   --role=roles/cloudkms.cryptoKeyEncrypter

# authorize access to the KMS key to _only_ the specific image hash
## we've already performed corse grain authorization on the workload pool and this step
## applies fine grain control to a specific image to decrypt data
gcloud kms keys add-iam-policy-binding key1        --keyring=kr1 --location=global --project $COLLABORATOR_1_PROJECT_ID    \
     --member="principalSet://iam.googleapis.com/projects/$COLLABORATOR_1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/attribute.image_reference/us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"  \
     --role=roles/cloudkms.cryptoKeyDecrypter
```

**Important**: use `"STABLE" in assertion.submods.confidential_space.support_attributes` for the pool definition for production  if you want to prevent the operator running the debug image family (`--image-family=confidential-space-debug`) **which allows SSH**.

At this point, the collaborator will only release access to a KMS key if they see a request originating from a trusted Confidential Space VM the operator runs and at that, from a specific image hash they had earlier trusted and authorized.

In other words, the use of the KMS key is now bound to the operator's project when it uses a confidential compute VM and furthermore, when the attestation token indicates the trusted image is used.  

Access is granted to an identity bound to the image:

```bash
principalSet://iam.googleapis.com/projects/$COLLABORATOR_1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/attribute.image_reference/us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f
```

We could have configured the entire workload provider to mandate that any access to any resource must include that specific image has.  This demo, however, abstracts it to the resource (KMS key) binding.  This was done to allow more operational flexibility: if the image builder creates a new image hash, each collaborator can more easily replace the IAM binding on specific resources instead of redefining the entire providers constraints.

>> **important** Note that since this is just a demo, the HTTP or pubsub message any collaborator sends is blindly used by application to access the KMS key.  So if  `collaborator-3` somehow could submit messages to the topic or post data over mTLS using certs, the application would go through the process to acquire their kms key and decrypt.  In reality, what you should do is have code or configuration that stipulates only a predefined set of collaborators can participate (eg, instead of the pubsub message itself feeding in the `audience` and `kmskey`, you have that set in code, config or container start args so that collaborator 1 and 2 knows that only their data is in the sandbox).

### Collaborator 2

We will do almost the same thing with collaborator-2 except that they define _their own_ workload pool, kms key and authorization levels.

This delegates access control to each collaborator

```bash
# switch
gcloud config configurations activate collaborator-2
export COLLABORATOR_2_GCLOUD_USER=`gcloud config get-value core/account`
export COLLABORATOR_2_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_2_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_2_PROJECT_ID --format='value(projectNumber)'`

gcloud services enable \
    pubsub.googleapis.com \
    cloudkms.googleapis.com \
    iam.googleapis.com pubsub.googleapis.com

gcloud iam workload-identity-pools create trusted-workload-pool --location="global"

# note the following allows the **production** conf-space image;  to allow the debug,
gcloud iam workload-identity-pools providers create-oidc attestation-verifier \
    --location="global"     --workload-identity-pool="trusted-workload-pool"   \
      --issuer-uri="https://confidentialcomputing.googleapis.com/"     --allowed-audiences="https://sts.googleapis.com" \
          --attribute-mapping="google.subject=assertion.sub,attribute.image_reference=assertion.submods.container.image_reference"  \
             --attribute-condition="assertion.swname=='CONFIDENTIAL_SPACE' && \"STABLE\" in assertion.submods.confidential_space.support_attributes && assertion.submods.gce.project_id=='$OPERATOR_PROJECT_ID' && 'operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com' in assertion.google_service_accounts"

gcloud kms keyrings create kr1 --location=global --project $COLLABORATOR_2_PROJECT_ID
gcloud kms keys create --keyring=kr1 --location=global --purpose=encryption  key1

# allow current user to encrypt so that we can test
gcloud kms keys add-iam-policy-binding key1        --keyring=kr1 --location=global --project $COLLABORATOR_2_PROJECT_ID    \
     --member="user:$COLLABORATOR_2_GCLOUD_USER"   --role=roles/cloudkms.cryptoKeyEncrypter

gcloud kms keys add-iam-policy-binding key1        --keyring=kr1 --location=global --project $COLLABORATOR_2_PROJECT_ID    \
     --member="principalSet://iam.googleapis.com/projects/$COLLABORATOR_2_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/attribute.image_reference/us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"  \
     --role=roles/cloudkms.cryptoKeyDecrypter
```

### Deploy 

We're now finally ready to deploy the Confidential Space VMs running that specific container


```bash
# switch
gcloud config configurations activate operator
export GCLOUD_USER=`gcloud config get-value core/account`
export OPERATOR_PROJECT_ID=`gcloud config get-value core/project`
export OPERATOR_PROJECT_NUMBER=`gcloud projects describe $OPERATOR_PROJECT_ID --format='value(projectNumber)'`
echo $OPERATOR_PROJECT_ID
echo $BUILDER_PROJECT_ID

### create the pubsub topic each collaborator will push encrypted data to
### the vm  will create will subscribe to messages to this topic using its own svc account (not a collaborators workload token)
gcloud pubsub topics create cs-topic
gcloud pubsub subscriptions create cs-subscribe --topic=cs-topic

gcloud pubsub subscriptions add-iam-policy-binding cs-subscribe \
  --member="serviceAccount:operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com" \
  --role=roles/pubsub.subscriber 

# allow both collaborators to submit messages to the topic
gcloud pubsub topics add-iam-policy-binding cs-topic \
  --member="user:$COLLABORATOR_1_GCLOUD_USER" \
  --role=roles/pubsub.publisher 

gcloud pubsub topics add-iam-policy-binding cs-topic \
  --member="user:$COLLABORATOR_2_GCLOUD_USER" \
  --role=roles/pubsub.publisher 

## allow the vm itself that has that service account permissions access to the attestation service
### note, we're applying this to all VM's in the project that use this specific service account
gcloud projects add-iam-policy-binding $OPERATOR_PROJECT_ID \
      --member="serviceAccount:operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com" \
      --role=roles/confidentialcomputing.workloadUser

# create the confidential space VM in our own subnet and instruct it to run the specific image hash from the builder's project 
# we are using the image-family=confidential-space here which does **NOT** allow SSH...we've also specified that this vm 
### https://cloud.google.com/compute/confidential-vm/docs/reference/cs-options

## There are two options, pick one: 
### A) start a VM with no external IP where collaborators use pubsub to send data
### B) start VM with external IP where collaborators use mTLS Certs and Pubsub to send data

### A) Using pubsub and no external IP
gcloud compute instances create vm1 --confidential-compute \
  --shielded-secure-boot --tags=tee-vm \
  --maintenance-policy=TERMINATE --scopes=cloud-platform  --zone=us-central1-a \
  --image-project=confidential-space-images \
  --image-family=confidential-space --network=teenetwork --no-address \
  --service-account=operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com \
  --metadata ^~^tee-image-reference=us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f~tee-restart-policy=Never~tee-container-log-redirect=true


### B) Using mTLS with external IP
gcloud compute firewall-rules create allow-tee-inbound \
 --network teenetwork --action allow --direction INGRESS    --source-ranges 0.0.0.0/0     --target-tags tee-vm    --rules tcp:8081

gcloud compute instances create vm1 --confidential-compute \
 --shielded-secure-boot --tags=tee-vm \
 --maintenance-policy=TERMINATE --scopes=cloud-platform  --zone=us-central1-a \
 --image-project=confidential-space-images \
 --image-family=confidential-space --network=teenetwork \
 --service-account=operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com \
 --metadata ^~^tee-image-reference=us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f~tee-restart-policy=Never~tee-container-log-redirect=true

export EXTERNAL_IP=`gcloud compute instances describe vm1 --zone=us-central1-a  --format='get(networkInterfaces[0].accessConfigs.natIP)'`
echo $EXTERNAL_IP

## for ssh access, set --image-family=confidential-space-debug and omit the `"STABLE" in assertion.submods.confidential_space.support_attributes`  in each collaborator pool/provider definition
# gcloud compute firewall-rules create allow-ingress-from-iap --network teenetwork --direction=INGRESS --action=allow --rules=tcp:22 --source-ranges=35.235.240.0/20
# gcloud projects add-iam-policy-binding $OPERATOR_PROJECT_ID  --member=user:$GCLOUD_USER --role=roles/iap.tunnelResourceAccessor
# gcloud projects add-iam-policy-binding $OPERATOR_PROJECT_ID --member=user:$GCLOUD_USER --role=roles/compute.instanceAdmin.v1
# gcloud compute ssh vm1 --tunnel-through-iap --zone=us-central1-a --project $OPERATOR_PROJECT_ID
```

You should see the startup sequence and subscription ready on the operator's GCE logs:

![images/cc_startup.png](images/cc_startup.png)

### Test

We can now test this by submitting encrypted messages to the topic


```bash
## submit some data as collaborator 1
gcloud config configurations activate collaborator-1
export COLLABORATOR_1_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_1_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_1_PROJECT_ID --format='value(projectNumber)'`

# gcloud auth application-default login

## For pubsub
cd pubsub_client/
go run main.go \
  --topicProject=$OPERATOR_PROJECT_ID \
  --user=alice \
  --kmsKey="projects/$COLLABORATOR_1_PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/key1" \
  --audience="//iam.googleapis.com/projects/$COLLABORATOR_1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier"

## For HTTP
cd http_client/
go run client.go   \
   --host $EXTERNAL_IP:8081 \
   --server_name=tee.collaborator1.com \
   --audience="//iam.googleapis.com/projects/$COLLABORATOR_1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier" \
   --kmsKey="projects/$COLLABORATOR_1_PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/key1" \
   --user=alice \
   --ca_files=certs/root-ca-collaborator1.crt \
   --tls_crt=certs/client-collaborator1.crt \
   --tls_key=certs/client-collaborator1.key   

# submit some data as collaborator2
gcloud config configurations activate collaborator-2
export COLLABORATOR_2_PROJECT_ID=`gcloud config get-value core/project`
export COLLABORATOR_2_PROJECT_NUMBER=`gcloud projects describe $COLLABORATOR_2_PROJECT_ID --format='value(projectNumber)'`

# gcloud auth application-default login

## For pubsub
cd pubsub_client/
go run main.go \
  --topicProject=$OPERATOR_PROJECT_ID \
  --user=alice \
  --kmsKey="projects/$COLLABORATOR_2_PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/key1" \
  --audience="//iam.googleapis.com/projects/$COLLABORATOR_2_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier"

## For HTTP
cd http_client/
go run client.go   \
   --host $EXTERNAL_IP:8081 \
   --server_name=tee.collaborator2.com \
   --audience="//iam.googleapis.com/projects/$COLLABORATOR_2_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/providers/attestation-verifier" \
   --kmsKey="projects/$COLLABORATOR_2_PROJECT_ID/locations/global/keyRings/kr1/cryptoKeys/key1" \
   --user=alice \
   --ca_files=certs/root-ca-collaborator2.crt \
   --tls_crt=certs/client-collaborator2.crt \
   --tls_key=certs/client-collaborator2.key      
```

If you happened to see the pubsub messages, you'll see the message data is encrypted:

![images/pubsub_message.png](images/pubsub_message.png)

The TEE should automatically process each message so what you'll see is a simple counter in the operator VM logs indicating the counter.  

Since both collaborators sent in `alice`, you'll see the count to 2

![images/cc_logs.png](images/cc_logs.png)

---

### Appendix

#### Audit Logging

You can enable audit logs for the collaborators, operators or builders

For the collaborators, enabled logs for workload federation and the KMS key

![images/collaborator_audit_logs.png](images/collaborator_audit_logs.png)

After deployment, you should see requests from the Confidential VM

for the token exchange:

![images/sts.png](images/sts.png)

and the actual KMS access

![images/kms.png](images/kms.png)

For the operator, you can enable vm logs for GCE

>> Important: these GCE logs are *NOT* audit logs and just plain VM logs...these can be [created/faked](https://gist.github.com/salrashid123/714a5b67f254eba6954333be8bc03c0c) by a user with log writer access manually so do not use them for a verifiable source of truth

### Logging

Logging to `stdout/stderr` is disabled for confidential space VMs.  Logging to stdout/stderr is only enabled with the debug image set but thats rarely used.

This repo addresses this by writing to `Cloud Logging` via the API itself.

GCP Cloud Logging must always be associated to a container project where the logs are written to.  This repo uses the `Operator` project and is constructed with labels to  appears logs with that vm as labels.  You will see _just_ the api based `LogEntries`  with `logName=projects/$OPERATOR_PROJECT_ID/logs/cs-log`.

![images/cloud_logging.png](images/cloud_logging.png)

In addition, the logs could even get written to any collaborator's GCP project.  In this mode, the container application will use workload identify federation to authenticate to the collaborators GCP project and use its logging api.


The `Launcher Spec` log line shown below

![image/launch_spec.png](images/launch_spec.png)

Describes a go struct denoting the [startup metadata](https://cloud.google.com/compute/confidential-vm/docs/reference/cs-options#cs-metadata):

(basically the specifications/signals sent during startup of the container)

### Reproducible Builds

Building an container image using `docker` is not deterministic and will produce different image hash values.

If the all participants in this tutorial need assurance that a specific, attested code is infact running in the workload, they all need to confirm the the code results in a specific container image hash (alternatively, they need assurance from a 3rd party a specific image hash does what its intended to do only)

In the most strict scenario, the builder of the image should devise some way to create consistent image hashes that each collaborator can independently verify.

There are several ways to do this

* `kaniko`

    This is the default mechanism shown in this repo. Images based of kaniko can be made reproducible via flag [link](https://github.com/salrashid123/cosign_kaniko_cloud_build) 

* `bazel`
   
   Bazel can build these types of images too but...see the sad state of bazel's [rules_docker](https://github.com/bazelbuild/rules_docker#status) and even then, using [rules_go](https://github.com/bazelbuild/rules_go/issues/3467) is challenging.

* `ko`

  Ko is designed for go applications and can also create reproducible images

* `buildah`

  see [https://tensor5.dev/reproducible-container-images/](https://tensor5.dev/reproducible-container-images/)


Note, i've observed a build using bazel and kaniko produces the different hashes for the same code...not sure what the case is (implementation or have some small variation i didn't account for; likely the override stated below)...eitherway, i did see builds are self-consistent and reproducible using the same tool

* Kaniko produces `tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f`
* Bazel produces `tee@sha256:5262ccfa1cd487a709e59985d8be011c6c512e179c6876d9c4ecb5f1f2bd91a9`

#### Bazel Overrides

The bazel build configuration in this repo works as is (it better!)...however it required several workarounds due to the way bazel's `rules_go` works with generated google api protos.  

Specifically if you upgrade the core libraries that inturn use generated protos that have [migrated](https://github.com/googleapis/google-cloud-go/blob/main/migration.md), you may have to setup the overrides for `com_google_cloud_go_logging` and `com_google_cloud_go_kms` as shown below.  You will have to also use `com_google_cloud_go_longrunning` at least at version `v0.4.1`

For more information, see [#3423](https://github.com/bazelbuild/rules_go/issues/3423#issuecomment-1441192410)


In this repo, the `go_repository{}` for the three libraries would have the following overrides.

```
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_repositories():
    go_repository(
        name = "com_google_cloud_go_logging",
        build_directives = [
            "gazelle:resolve go google.golang.org/genproto/googleapis/longrunning @org_golang_google_genproto//googleapis/longrunning",  # keep
            "gazelle:resolve go google.golang.org/genproto/googleapis/logging/v2 @org_golang_google_genproto//googleapis/logging/v2:logging",  # keep
        ],
        importpath = "cloud.google.com/go/logging",
        sum = "h1:ZBsZK+JG+oCDT+vaxwqF2egKNRjz8soXiS6Xv79benI=",
        version = "v1.6.1",
    )
    go_repository(
        name = "com_google_cloud_go_longrunning",
        importpath = "cloud.google.com/go/longrunning",
        sum = "h1:v+yFJOfKC3yZdY6ZUI933pIYdhyhV8S3NpWrXWmg7jM=",
        version = "v0.4.1",
    )
    go_repository(
        name = "com_google_cloud_go_kms",
        build_directives = [
            "gazelle:resolve go google.golang.org/genproto/googleapis/cloud/kms/v1 @org_golang_google_genproto//googleapis/cloud/kms/v1:kms",   # keep
        ],        
        importpath = "cloud.google.com/go/kms",
        sum = "h1:OWRZzrPmOZUzurjI2FBGtgY2mB1WaJkqhw6oIwSj0Yg=",
        version = "v1.6.0",
    )
```

If you upgrade any of these libraries, remember to run `gazelle` to regenerate the `repositories.bzl` and then replace the `build_directives` section on the new set.

#### VPC-SC

You can also restrict KMS and Workload Federation (STS) API calls on each Collaborator by the collaborator:

Each collaborator can define their own [VPC-SC](https://cloud.google.com/vpc-service-controls/docs/overview) perimeter that says:

_"only allow workload federation and kms api calls to decrypt data if it originates from THIS operator projectID"_

This will prevent anyone that gets hold of the TEE's identity token _or_ access_token and accessing the KMS service from a coffee shop (which..would be bad)

For more information, see [Google Cloud VPC-SC basic ingress and egress rules](https://blog.salrashid.dev/articles/2021/vpc_sc/)

Here is a sample VPC-SC policy a collaborator and implement:

```bash
gcloud config configurations activate collaborator-1

gcloud access-context-manager perimeters describe collaborator_1_perimeter
```

```yaml
status:
  ingressPolicies:
  - ingressFrom:
      identityType: ANY_IDENTITY
      sources:
      - resource: projects/OPERATOR_PROJECT_NUMBER
    ingressTo:
      operations:
      - methodSelectors:
        - method: '*'
        serviceName: sts.googleapis.com
      - methodSelectors:
        - method: '*'
        serviceName: cloudkms.googleapis.com
      resources:
      - projects/COLLABORATOR1_PROJECT_NUMBER
  resources:
  - projects/COLLABORATOR1_PROJECT_NUMBER
  restrictedServices:
  - cloudkms.googleapis.com
  - sts.googleapis.com
  vpcAccessibleServices:
    allowedServices:
    - RESTRICTED-SERVICES
    enableRestriction: true
title: collaborator_1_perimeter
```

Note, VPC-SC "ingressPolicy->ingressFrom->identity" does not support `principal://` or `principalSet://` get so we have to enable `ANY_IDENTITY`.  Ideally, we could tune the identity to:

```bash
principalSet://iam.googleapis.com/projects/$COLLABORATOR1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/attribute.image_reference/us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f
```

If the TEE attempts to access the STS or KMS endpoint for any collaborator who _has not_ authorized the project for ingress, they would see a VPC-SC error at the level where the API is invoked.  In the following, the even the token grant fails

![images/vpc-sc.png](images/vpc-sc.png)


#### mTLS using acquired Keys

The object that is decrypted within a TEE can easily be a keypair used to establish or receive an mTLS connection.  

For outbound, a collaborator may choose to send an mTLS keypair to the TEE which it then uses to make a new connection to a service which expects that that client certificate.

There are several ways to achieve this where a pregenerated collaborator provided TLS CA and key pair is surfaced through a collaborator's own `Secret Manager` or using `GCP Private CA` to sign a CSR. (i.,e, instead of making KMS API calls back to a collaborators KMS syste, each collaborator unseals their secret or issues their own x509 within the TEE)

You can find basic examples of seeding a generic key into secret manager or issuing a cert via private ca [here](https://gist.github.com/salrashid123/f06eacd80a25611a7c322d8e6f99942f)

For inbound traffic, its the same but you can use one listener port that enforces different collaborators mtls CAs.  In this mode, each collaborator seeds the TEE with its own CA for client certs and its own server certificates.

A client will connect to the common listner port and perform mTLS using a client cert issued by a specific collaborators CA.  The client can also validate the server certificate was issued by that CA.  You can find an example of that at

* [go mTLS with multiple certificate issuers and OCSP verification](https://github.com/salrashid123/go_mtls_scratchpad#tls-config-without-client-ca).

The repo here contains a basic example of this techinque:  if the server TLS certificates were materialized on startup (i.,e these keys were delivered to the TEE by each individual collaborator)

```golang
	// load the server certs issued by both ca1 and ca2, pretend these should use get loaded
	// from each collaborators's secret manager or private ca using the attestation token (similar to the KMS decryption)
	server1_cert, err := tls.LoadX509KeyPair(*collaborator1_tls_crt, *collaborator1_tls_key)

	server2_cert, err := tls.LoadX509KeyPair(*collaborator2_tls_crt, *collaborator2_tls_key)
```

Then the TEE will startup and enforce mTLS by specifing the exact client CA that should be honored based on the SNI and reject all other inbound traffic

```golang
	tlsConfig := &tls.Config{
		GetConfigForClient: func(ci *tls.ClientHelloInfo) (*tls.Config, error) {
			if ci.ServerName == "tee.collaborator1.com" {
				return &tls.Config{
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  client1_root_pool,
					GetCertificate: func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return &server1_cert, nil
					},
				}, nil
			}
			if ci.ServerName == "tee.collaborator2.com" {
				return &tls.Config{
					ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs:  client2_root_pool,
					GetCertificate: func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return &server2_cert, nil
					},
				}, nil
			}
			return nil, fmt.Errorf("SNI not recognized %s", ci.ServerName)
		},
	}
```

Essentially, the client *must* present a client certificate issued exclusively the CA and client certificates associated with their collaborator.

Altarnatively, the mtls connection can be used to in a 'multi-party' capability which different collaborators each holds their keysiare which is used together to create the TLS connection.  This idea is explored in the following repo:

- [Multiparty Consent Based Networks (MCBN)](https://github.com/salrashid123/mcbn)

You can also achive `TEE->TEE` traffic for a single trusted collaborator by using boot/init containers that acquire the mTLS certificates.  This is decribed in

* [mTLS proxy containers for GCP Confidential Compute](https://github.com/salrashid123/tee_server_proxy)

Finally, you can also establish an mTLS connection where the private key resides in your KMS system.

In this mode, you will issue a new KMS key and grant the Confidential Space VM access to that kMS key.

For more information, see 

- [mTLS with Google Cloud KMS](https://blog.salrashid.dev/articles/2022/kms_mtls/)

Much more commonly, a TEE will just unwrap an x509 or keypair directly within the TEE and use that as described earlier.

#### Service Discovery and TEE-TEE traffic

Networking between TEEs necessarily needs to be done over TLS or preferably mTLS using the one of the techniques outlined in the sections above.  

Basically, the `TEE->TEE` traffic first needs one TEE to discovery the address resolution of another TEE peer.  Once thats done, the TLS connection needs to be such that they 'trust each other' (see mTLS section)

There are many ways to establish service disovery of the TEE cluster/peers depending on the topoloy.  The service discovery system by itself can be hosted entirely by the operator in this case if the peer TLS is mutually trusted by bootstrapping after attestation.   In other words, even if the operator injects false TEE peer addresses, a client TEE cannot establish a TLS connection with the server since the server would not have bootstrapped mTLS credentials.

Anyway, the various service discovery mechanisms

* [DNS Based Service Directory with HTTP and TCP Internal Load Balancer](https://gist.github.com/salrashid123/93d899503d5799f10745a9fe7c89de87)

  With this, the GCP Service Directory is used to specify the address of an internal load balancer for a group of TEE backends

* [Proxyless gRPC with Google Traffic Director](https://github.com/salrashid123/grpc_xds_traffic_director)

  With this, each gRPC client acquires peer addresses from Traffic Director

* [Hashicorp Consul JWT Auth](https://github.com/salrashid123/consul_jwt_auth)

  Uses an external service where each client 'registers' itself to consul by presenting it with an OIDC attestation token


You can also ensure `TEE->TEE` traffic by running a proxy that acquires certificates first before delegating the request to the backend (see example below for envoy network proxy).  Alternatively, the target TEE would acqquire the certificates and exec the target service's native tls configuration (see example below for redis and postgres ) You can find an example of that here:

* [mTLS proxy containers for GCP Confidential Compute](https://github.com/salrashid123/tee_server_proxy)

To ensure multiple parties consent to the tee->tee traffic, thats a lot harder and experimental (see prior section)


#### Attestation Token and JWT Bearer token

For reference, here is a sample decoded attestation JWT

Do **NOT** transmit this token to any other external system.   While its true a remote system _could_ use this as a bearer token, you would potentially compromise the security of other collaborators (i.,e a remote system can just use this token to access another collaborator's KMS key).

Instead, you can generate a JWT token using another KMS key you have access to though [golang-jwt for crypto.Signer](https://github.com/salrashid123/golang-jwt-signer) or simply use a secret decrypted with an initial bootstrapped KMS key.

- `/run/container_launcher/attestation_verifier_claims_token`

```json
{
  "aud": "https://sts.googleapis.com",
  "exp": 1683607320,
  "iat": 1683603720,
  "iss": "https://confidentialcomputing.googleapis.com",
  "nbf": 1683603720,
  "sub": "https://www.googleapis.com/compute/v1/projects/vegas-codelab-5/zones/us-central1-a/instances/vm1",
  "tee": {
    "version": {
      "major": 0,
      "minor": 0
    },
    "platform": {},
    "container": {
      "image_reference": "",
      "image_digest": "",
      "restart_policy": "",
      "image_id": "",
      "env_override": null,
      "cmd_override": null,
      "env": null,
      "args": null
    },
    "gce": {}
  },
  "secboot": true,
  "oemid": 11129,
  "hwmodel": "GCP_AMD_SEV",
  "swname": "CONFIDENTIAL_SPACE",
  "swversion": [
    "1"
  ],
  "dbgstat": "disabled-since-boot",
  "google_service_accounts": [
    "operator-svc-account@vegas-codelab-5.iam.gserviceaccount.com"
  ],
  "submods": {
    "container": {
      "image_reference": "us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f",
      "image_digest": "sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f",
      "restart_policy": "Never",
      "image_id": "sha256:ea901e29de82397b78616fb98cb7d5d09afeb11b804ac98dabcd77208e79ea41",
      "env_override": null,
      "cmd_override": null,
      "env": {
        "HOSTNAME": "vm1",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt"
      },
      "args": [
        "./server"
      ]
    },
    "gce": {
      "zone": "us-central1-a",
      "project_id": "vegas-codelab-5",
      "project_number": "75457521745",
      "instance_name": "vm1",
      "instance_id": "6920867375712861823"
    },
    "confidential_space": {
      "support_attributes": [
        "LATEST",
        "STABLE",
        "USABLE"
      ]
    }
  }
}
```

#### Authenticating with other Cloud Providers

The KMS keys the collaborators granted access to is a generic decryption key:  you can use it to unwrap any arbitrary access tokens for any other cloud provider.  

For example, the encrypted data that is returned need not be just some text as in the example here but any AWS or Azure credential set which you can use to access any other service's APIs.

Just as a side note, you can also keep access secrets still within KMS systems (vs beaming them down).  In this mode, any access to other cloud providers requires GCP KMS key access.

For example

* [KMS, TPM and HSM based Azure Certificate Credentials](https://blog.salrashid.dev/articles/2022/azsigner/)
* [Embedding AWS_SECRET_ACCESS_KEY into Trusted Platform Modules, PKCS-11 devices, Hashicorp Vault and KMS wrapped TINK Keyset](https://blog.salrashid.dev/articles/2021/aws_hmac/)
  
    Unfortunately, at the moment GCP KMS limits the keysize you can [import to  32bytes!](https://blog.salrashid.dev/articles/2021/hmac_sha_key_size/)....which is less than an AWS Secret size...meaning, you can't use this mechanism for aws


You maybe tempted to setup GCP Workload Federation with other cloud providers from the TEE as shown here

* [Federate Google Cloud OIDC tokens for Azure Access Tokens](https://blog.salrashid.dev/articles/2022/azcompat/)
* [Federate Google Cloud OIDC tokens for AWS Access Tokens](https://blog.salrashid.dev/articles/2022/awscompat/)

However, you can't use the TEE attestation oidc token (for the reason described earlier)...nor can you use the VM's [instance identity document](https://cloud.google.com/compute/docs/instances/verifying-instance-identity) since any VM (Confidential Space or otherwise) in operator's project would surface that same google OIDC token specifications.

#### Outbound traffic via NAT

The operator can also create a [NAT gateway](https://cloud.google.com/nat/docs/overview) which will give a predictable egress address for non-google api outbound traffic.

Each collaborator can use this predictable address in additional network-based ACLs on their end.

The operator can get the NAT IP address by running:

```bash
$ gcloud compute addresses describe natip --region=us-central1 --project $OPERATOR_PROJECT_ID
address: 34.66.148.162
```

#### Client-side Encryption

Its advisable to wrap (encrypt) any data that is transmitted on the wire through a cloud provider.  

For example, if you send pubsub messages, do what is described here by encrypting the data first, then transmitting it and then finally decrypting it on the TEE.

The same technique can be used for GCS data as shown here:

- [Message Payload Encryption in Google Cloud Pub/Sub](https://blog.salrashid.dev/articles/2018/pubsub_message_encryption/)
- [Google Cloud Storage client-side Stream encryption with gsutil and TINK](https://blog.salrashid.dev/articles/2022/gcs_stream_encryption/)


#### Using BigQuery

In certain cases, it maybe acceptable if a Cloud Provider's service outside the TEE decrypts and processes some data from both parties.  

In this mode, suppose collaborator-1 and -2 encrypts some sensitive data using their own AES encryption keys compatible with [BQ AEAD Functions](https://cloud.google.com/bigquery/docs/reference/standard-sql/aead_encryption_functions).  Their data is encrypted at rest and is only accessible in its raw form to BigQuery if each collaborator supplies their decryption keys within the query.

BigQuery's infrastructure will use each collaborators key to decrypt their respective data and execute the query.  The provided key paramter [will not be stored or audit logged](https://cloud.google.com/bigquery/docs/parameterized-queries)

The output maybe anonymized data seeded back to the TEE or written to another dataset. 

If this variation of Confidential Space is acceptable (i.e each collaborator trust BigQuery but not the collaborator or operator), then a sample query originating from within the TEE may look like this where `keyset1` and `keyset2` are the parts decrypted first within a TEE by the collaborator's KMS keys


Consider each collaborator has encrypted some data with their own AEAD keys:

* `collaborator-1`

```bash
$ bq  query \
  --parameter=keyset1::CNXd6toHEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIDnvckhhXod0bLVuBGIrCHiCl14aUkBeN8MaBiimapLZGAEQARjV3eraByAB --use_legacy_sql=false  'SELECT
  customer_id, encrypted,  AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),
   ecd1.encrypted,
   "somedata"
 )
FROM COLLABORATOR_1_PROJECT_ID.aead.join AS ecd1;'
+-------------+------------------------------------------------------+-------+
| customer_id |                      encrypted                       |  f0_  |
+-------------+------------------------------------------------------+-------+
| alice       | AXtartUCTC8Ei2xJf4uGs8GE42PLkC+yjoGagdD46FRwCH7BQxA= | liger |
| bob         | AXtartXXTJOVqxN1zJ0zd4jaGPcJaBpTCpxwz3Ovze6b2jh+6TE= | robin |
| carol       | AXtartVWVMV8MT7Q8xOUTyzteG4AeR6L41NOjaUffDa2V70yZ0k= | panda |
+-------------+------------------------------------------------------+-------+
```


* `collabortor-2`

```bash
bq  query \
  --parameter=keyset2::CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB --use_legacy_sql=false  'SELECT
  customer_id, encrypted,  AEAD.DECRYPT_STRING(FROM_BASE64(@keyset2),
   ecd2.encrypted,
   "somedata"
 )
FROM COLLABORATOR_2_PROJECT_ID.aead.join AS ecd2;'

+-------------+----------------------------------------------------------+---------+
| customer_id |                        encrypted                         |   f0_   |
+-------------+----------------------------------------------------------+---------+
| jeff        |     AZrLBELOisdB8axEPXQ3YXAvbzkl1egqz6nULrkDbLFTfK6Q60qm | rabbit  |
| eric        |     AZrLBELeIrrscwsCw2fqo/QDarrupvjVtI7vKX7pkOoj2awODq0= | liger   |
| victor      |     AZrLBEKfkqVMBsHDq2uMXCArOWgd6Q8KWEUDWGgOSBDrCd34ZKc= | panda   |
| karen       | AZrLBEKYIAhdSDLUF76qcyjQE9vb5mnUeRUhZCv7ONrb5rGhQAQvQA== | sparrow |
+-------------+----------------------------------------------------------+---------+
```

* `Operator`

  The TEE can use KMS to decrypt each collaborator's AEAD keys and submit a query like this which identifies which users in the respective datasets has the same encrypted data.  In this case, the pairs `(alice,eric)`, `(carol,victor)` has the same encrypted data  

```bash
bq  query \
--parameter=keyset1::CNXd6toHEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIDnvckhhXod0bLVuBGIrCHiCl14aUkBeN8MaBiimapLZGAEQARjV3eraByAB \
--parameter=keyset2::CMKIrNYJEmQKWAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EiIaIGNoYW5nZSB0aGlzIHBhc3N3b3JkIHRvIGEgc2VjcmV0GAEQARjCiKzWCSAB \
--use_legacy_sql=false  'SELECT
  ecd1.customer_id as cid1, ecd2.customer_id as cid2
FROM COLLABORATOR_1_PROJECT_ID.aead.join AS ecd1,
     COLLABORATOR_2_PROJECT_ID.aead.join AS ecd2
WHERE AEAD.DECRYPT_STRING(FROM_BASE64(@keyset1),
  ecd1.encrypted,
  "somedata"
) = AEAD.DECRYPT_STRING(FROM_BASE64(@keyset2),
  ecd2.encrypted,
  "somedata"
);'

+-------+--------+
| cid1  |  cid2  |
+-------+--------+
| alice | eric   |
| carol | victor |
+-------+--------+
```

Just note that in this context, the service account the TEE runs as (`operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com`) will require access to query over the _encrypted_ datasets each provider has.  It does not have access to decrypt any of it...that part is only available with the inline keysets provided with the query as shown above.  (see [example](https://gist.github.com/salrashid123/c358b29c0d738767435c92a9291feb56))

You can read more about this here "[BigQuery Client-side Encryption using AEAD](https://blog.salrashid.dev/articles/2022/bq_client_side_aead/#untrusted-multiparty-compute)"

Some notes and extras:

* [Importing and extracting external keys for BigQuery AEAD Tink KeySets](https://blog.salrashid.dev/articles/2021/bq_aead/)
* [AEAD Encryption with BQ Remote Functions](https://blog.salrashid.dev/articles/2022/bq_aead_remote_function/)
* [Bring your own Key for BigQuery SQL column-level encryption](https://blog.salrashid.dev/articles/2022/bq_kms/)
  
  BQ Column level encryption isn't practical here since it currently relies on KMS key access (i.,e the client that issues the BQ request must have access to _both_ provider's KMS keys used to encrypt the BQ data...This breaks some of the contracts and conditions we are using here)
* [BigQuery Customer Managed Encryption Keys](https://cloud.google.com/bigquery/docs/customer-managed-encryption)
  
  BQ allows datasets encryption at rest using your own KMS keys.  However, this form of encryption does not really help here since the single serivce account that issues the BQ Query `bq-$OPERATOR_PROJECT_NUMBER@bigquery-encryption.iam.gserviceaccount.com` would need access to both CMEK encrypted dataset.  If that were the case, the operator could create any new VM, associate that service account to that VM and issue queries and read data against both collaborators datets in cleartext.

#### Using BigQuery ML

You can use a similar technique describe above with [Bigquery ML](https://cloud.google.com/bigquery-ml/docs/introduction).  

There are several options available in this mode:

a. `collaborator-1`, `collaborator-2` each provides sensitive _data_ which the `operator` (or even a new `collaborator-3`) who can use that to _train_ an ML Model.  The model would be owned by the project where the training occurs (eg, either the `operator` or `collaborator-3`)

b. TEE runs `ML.PREDICT()` given sensitive data that over an already trained model that not even the operator has access to. 

For a contrived end-to-end example where a BQML model is generated with this technique, see [Bigquery ML over AEAD encrypted data](https://gist.github.com/salrashid123/12243b99771d22ed4d02a6f1094f624a)


#### Using CloudSQL

While you might be tempted to use the same technique as BigQuery encryption with CloudSQL-postgres `pgcrypto` extension, the bind parameters would be logged.

Postgres has server-side settings that would allow logging of these encryption keys which is not be desireable by the client submitting the query (you don't want your keys to get logged!)

Its _possible_ to detect if server-side logging is enabled with ClouSQL if the client issues the query can first check if postgres as bind parameter logging enabled or not:

```sql
select setting from pg_settings where name = 'log_parameter_max_length';
select setting from pg_settings where name = 'log_parameter_max_length_on_error';
```

At the moment (11/16/22), GCP CloudSQL Postgres _does not allow_ you to set these values (its a pending feature)

Once it does, GCP CloudSQL [does not allow superuser](https://cloud.google.com/sql/docs/postgres/users#superuser_restrictions) logins so one the settings above are verified, the client can submit the query (**NOTE**: take that with a big grain of salt; i do not know postgres and there maybe other vectors to surface the bind parameters)

Anyway,  following the same technique as BQ, the column data for each collaborator is encrypted using their AES keys which each releases to the TEE is described at

* [Postgres Encrypted columns using pgcrypto on Google CloudSQL](https://gist.github.com/salrashid123/b8fb527c9577ceacb2c3fe5807eae98e)

#### Using SecretManager

[SecretManager](https://cloud.google.com/secret-manager/docs/overview) can be used as an alternative to KMS encrypted keys if the nature of the sensitive data is more appropriate for secrets-based transfer rather than wrapped encryption.

For example, suppose each collaborator's secret is actually a database passphrase or asymmetric key they save as versions in secret storage.  In this case, it probably makes more sense to save the sensitive data as a GCP Secret rather than transferring a wrapped KMS encrytped blob.

To use SecretManager in this mode is trivial: simply substitute the KMS IAM authorization and API calls for SecretManager.

#### Using WebAssembly to run Sensitive Container Code

In certain cases, the actual code that is executed inside the container maybe considered sensitive (eg, some specific formula, ML model, etc).

If this is the case, you do not want the Operator to have access to download the container image that includes this code in raw form.   

In this repo, the operator was already given access to download the image through the IAM binding we performed earlier (i.,e the operator alrady controls this service account and can unilaterally download the container image):

```bash
gcloud artifacts repositories add-iam-policy-binding repo1 \
    --location=us-central1  \
    --member=serviceAccount:operator-svc-account@$OPERATOR_PROJECT_ID.iam.gserviceaccount.com \
    --role=roles/artifactregistry.reader
```

One option to workaround this is to only have the sensitive code available inside the container only _after_ the container uses the TEE Attestation token to download and run the code.

For example, consider the following code snippet which uses [wasmer](https://github.com/wasmerio/wasmer-go) (a go runtime for webassembly)

Working with this [gist example code](https://gist.github.com/salrashid123/02940fc66c49f323aa25cd52d4407ae6), the sensitive data would be the `add()` typescript function thats compiled into webassembly and saved as the `hello-world.wasm` file in a secure GCS bucket owned by the owners of the IP.

When the TEE image starts up, it acquires its attestation token and uses workload federation to access the wasm file from the owners of the IP (i.e replace the `ioutil.ReadFile` with [object reader](https://pkg.go.dev/google.golang.org/cloud/storage#hdr-Objects))


#### Running Sensitive Machine Learning Code

If what the container runs is actually sensitive generic python or machine learning code (eg `Tensorflow` Model) which you do not want the operator to view, a model author can save an encrypted form of the machine learning model or code and only download or decrypt it after attestation.

For example, if you're dealing with an ML model you deem sensitive, you can [export/import a tensosorflow model](https://www.tensorflow.org/tutorials/keras/save_and_load#save_the_entire_model).  For this, the entire model is saved or encrypted and only visible (decrypted) within the TEE after attestation.  For an example of searilizing and loading a tensorflow model, see  

* [Saving and loading TensorFlow serialized models](https://gist.github.com/salrashid123/0e6f5a1a11bc12ab21306c1e1ce94fed)

If you're just attempting to serialize a simple class, you can use a library like [dill](https://dill.readthedocs.io/en/latest/) to serialize that class and then encrypt it with a KMS key. For example, if the following funciton [RCE()](https://gist.github.com/salrashid123/545c8e8b2b07746fdb8c2a15805ef242) is deemed sensitive, then you can use dill to decrypt it inside the TEE.


#### Using Hashicorp Vault

If you have an on-prem [Hashicorp Vault](https://www.vaultproject.io/) which saves encryption keys, you can access it from within the TEE by passing through a GCP KMS encrypted `VAULT_TOKEN`, unwrapping it within the TEE.

Alternatively, you can just use Vault's [JWT Auth](https://developer.hashicorp.com/vault/docs/auth/jwt) mechansim.

In this mode, you use the TEE's attestation token and emit that to your vault server.  The vault server validates the TEE specicifcations and returns a `VAULT_TOKEN` for the TEE to use again.

>> Note: you _are_ emitting the TEE's attestation token externally here.  Earlier on in this tutorial, we mentioned that you should not emit this token in a multiparty system (eg, to prevent replay or compromise another collaborator security).  However, if you are the _only_ collaborator, you can emit the token to your own VAULT server.

Critically, also note that the TEE attestation token has a fixed audience value (`https://sts.googleapis.com`).  If you sent this TEE token to your vault server as-is, you are somewhat misusing the intent for that claim and token (i.,e its intended auidence is GCP's STS server; not your vault server). 

Once Confidential Space allows custom audiences,  you can use this VAULT auth mechansim against multiple collaborators onprem server as well as GCP APIs since you can define your own audience settings.

In short, its not recommened to use this mechanism but the following is there for completeness:

Anyway, here is a sample Vault JWT configuration that would authorize a specific image similar to the workload federation done in this tutorial.

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
  "bound_audiences": ["https://sts.googleapis.com"],
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
    "/submods/container/image_digest": ["sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"],
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


#### Threshold Encryption and Signatures

You can also easily use the TEE to perform [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem) functions like signing or encryption/decryption.

In this mode, each collaborator's threshold key is encrypted by their own KMS key and is decrypted within the TEE.

Once the TEE receives the `t of n` keys, it can perform encryption or signing per key-type.

The following uses [go.dedis.ch/kyber](https://pkg.go.dev/go.dedis.ch/kyber) library and writes the public and private keys in binary to a file.  

For use with KMS, each participant would encrypt the binary form of the marshalled key first and transmit that content to the TEE for decryption.

* [Threshold Signatures](https://gist.github.com/salrashid123/c936fcbaa40c403232351f67c17ee12f)
* [Threshold Encryption](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13)

#### Container image signing and verification

Confidential Space has no built in capability for [Cryptographic Signing for Containers](https://aws.amazon.com/blogs/containers/cryptographic-signing-for-containers/) or any way to ensure that N parties provided their [signatures against the image](https://blog.sigstore.dev/cosign-image-signatures-77bab238a93/) itself. As a side note, a container signature is actually the hash of json formatted file which includes the image manifests digest itself (see [this example](https://gist.github.com/salrashid123/4138d8b6ed5a89f5569e44eecbbb8fda))

While each collaborator can ensure a specific image hash is exclusively authorized to access their KMS key, there is no direct mechanims that ensures the container was approved and authorized (i.,e signed) by outside parties.

GCP provides [binary authorization](https://cloud.google.com/binary-authorization) which seeks to only allow a specific container to be _deployed_ to managed services like GKE, Cloud Run and Anthos if N parties provided [attestations](https://cloud.google.com/binary-authorization/docs/attestations) by means of a signature.

In the case of Confidential Space, the operator is in charge of the deployment which means if each collaborator needs to ensure N parties provided their signatures, they cannot rely on deployment admission controllers because that is not detached from the operators control.

There are several alternatives where the signature checks happen during runtime (late binding) or prior to authorizing the image for KMS access (early binding)

- `early binding`

  If a collaborator wants to ensure that the operator or some third party submitted/attested the container+hash, the collaborator can "just verify" that was done prior to authorizing the container for KMS access.

  This would require the workflow pipleine for each collaborator to get notification of a new candidate image for deployment, then check if the requsite signatures were provided and only then authorize KMS access specifically for that image.

  The specific workflows involved for the notification and verification of candidate containers is implementation dependent and is not covered here.

  If `sigstore/cosign` is used the collaborator would need to iterate over the public keys for each attestor he/she is interested in and then once satisfied, proceed to authorize the image.   The section below describes using cosign cli and api to verify containers.

  If [gcp binary authorization](https://cloud.google.com/binary-authorization) is used by the operator as the "signature system", the collaborator can verify N parties provided signatures by invoking the operators binary authorization api, then reading and verifying which parties provided signatures (eg the collaborator would run `gcloud beta container binauthz attestations list --attestor=myattestor --project=$OPERATOR_PROJECT_ID` prior to authorization). A more formal confirmation that signatures were provided could be if the operator enabled GCP Audit Logs for the binaryauthorization API.  If that step is done, each attestation is encoded in the operators audit log permanently.  [Here](https://gist.github.com/salrashid123/2ca607fee4977244136cb1ae0d37173f) is an example of Binary Authorization Audit Log.  Once in audit log, the collabortors can subscribe to events via GCP [eventarc](https://cloud.google.com/eventarc/docs/event-driven-architectures) which can notify of any new signatures or changes.   

  Finally, authorizing at a per image hash scope is made a bit easier with this repo since it does _not_ setup full authorization at the [workload provider and pool](https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds#oidc) level and instead sets it at the resource IAM binding:
  
  ```bash
  gcloud kms keys add-iam-policy-binding key1        --keyring=kr1 --location=global --project $COLLABORATOR_1_PROJECT_ID    \
     --member="principalSet://iam.googleapis.com/projects/$COLLABORATOR_1_PROJECT_NUMBER/locations/global/workloadIdentityPools/trusted-workload-pool/attribute.image_reference/us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"  \
     --role=roles/cloudkms.cryptoKeyDecrypter
  ```

  This allows for multiple, rapid IAM binding at the resource per image without defining a new pool.


- `late binding`

  With late binding, the cotntainer on startup checks for the requsite signatures during the applications `init()` stage.  
  
  In other words, the acutual container code uses a set of public keys to verify the image hash it is running with has a valid signature against it either with cosign or in gcp's binary authorization system or simply read the signatures passed as startup arguments to the container runtime.  An image could derive its own image_hash by  locally verifying its JWT Attestation token.
  
  This mechanism is described in detail below

#### Check Cosign Signature and Attestation at Runtime

Confidential space does not currently verify if the image being deployed was signed by various parties with any attestations.  

This is where [cosign](https://github.com/sigstore/cosign) can help add a participant or third party siganatures to the images.

In the example here,  the builder's generated sigature is added in during the cloudbuild steps using the builders's KMS key.  

To check the cosign signatures and attestations, install cosign and then:

```bash
### verify with cosign
## first login to ADC as the builder
## gcloud config configurations activate builder
## export BUILDER_PROJECT_ID=`gcloud config get-value core/project`
## export BUILDER_PROJECT_NUMBER=`gcloud projects describe $BUILDER_PROJECT_ID --format='value(projectNumber)'`
## gcloud auth application-default login
$ cosign tree      us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f

📦 Supply Chain Security Related artifacts for an image: us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f
└── 💾 Attestations for an image tag: us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee:sha256-a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f.att
   ├── 🍒 sha256:cf47d0e4b5497f43ca9fc1010aeff66ad090539c9c209c421f8880693b8ad20f
   └── 🍒 sha256:ffe6fd0cf1d33f675e0d15449a155b67824f52bcb00b9b895d2d8dac0ca4f436
└── 🔐 Signatures for an image tag: us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee:sha256-a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f.sig
   └── 🍒 sha256:28d0920083646f1f4d7e945f1c9dc2eda7881df81ef36c4b5df9dac925138e0c
└── 📦 SBOMs for an image tag: us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee:sha256-a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f.sbom
   └── 🍒 sha256:2c011edec264809e797e4d37068792dafaadb87f772a72ae0eb5bf3db90299c3
```

which will exist as additional artifacts in the registry

![images/artifacts.png](images/artifacts.png)

```bash
# get the public key for the cosigned image
gcloud kms keys versions get-public-key 1  \
  --key=key1 --keyring=cosignkr \
  --location=global --output-file=/tmp/kms_pub.pem

## verify 
# you can also reference the kms key via url instead of using a local one
#   for that use --key gcpkms://projects/$BUILDER_PROJECT_ID/locations/global/keyRings/cosignkr/cryptoKeys/key1/cryptoKeyVersions/1 

cosign verify --key /tmp/kms_pub.pem   \
   us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f  | jq '.'

# the output for the verify will look like:

Verification for us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[
  {
    "critical": {
      "identity": {
        "docker-reference": "us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee"
      },
      "image": {
        "docker-manifest-digest": "sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "key1": "value1"
    }
  }
]

# now verify the attestation that is cross checked with the rego in `policy.rego` (cosign_verify/policy.rego)
#  (all that this rego validates is if foo=bar is present in the predicate (which we did during the cloud build steps))
cosign verify-attestation --key /tmp/kms_pub.pem --policy cosign_verify/policy.rego    \
      us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f  | jq '.'


Verification for us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjAuMSIsInByZWRpY2F0ZVR5cGUiOiJjb3NpZ24uc2lnc3RvcmUuZGV2L2F0dGVzdGF0aW9uL3YxIiwic3ViamVjdCI6W3sibmFtZSI6InVzLWNlbnRyYWwxLWRvY2tlci5wa2cuZGV2L21pbmVyYWwtbWludXRpYS04MjAvcmVwbzEvdGVlIiwiZGlnZXN0Ijp7InNoYTI1NiI6ImE3NmZkNDBkODUxZDg5NWY2ZWVlMmIwNDdjZWFmODRmY2IwNjgxMmVmMTcwN2RiYzlhMjJlNGU3NGY0Y2ZkMWYifX1dLCJwcmVkaWNhdGUiOnsiRGF0YSI6InsgXCJwcm9qZWN0aWRcIjogXCJtaW5lcmFsLW1pbnV0aWEtODIwXCIsIFwiYnVpbGRpZFwiOiBcImFkMTMyMzBiLTlmYmQtNDA3NC1hYTA5LTQyNDNiYzdjN2Y2NlwiLCBcImZvb1wiOlwiYmFyXCIsIFwiY29tbWl0c2hhXCI6IFwiYzc0Yjk1ZDU3NzU1NTQ4MjA3MmE3OTMzZGY4MTEzZTU4M2E0ZDM2OVwifSIsIlRpbWVzdGFtcCI6IjIwMjMtMDUtMDlUMDM6Mzc6MDNaIn19",
  "signatures": [
    {
      "keyid": "",
      "sig": "MEUCIQDGCzFvlbbVM3msykva+PijsdrbwGBJ5EKBEHGp6J8TmwIgdt2rqQbqFR5Hye0L82pBYFrQ85ldAw9T0V5j1Pt/Hjg="
    }
  ]
}


## if you decode the payload, you'll see the predicate and image attestations (build number, commit hash, timestamp and the prediecate KV pair we sent during build (foo=bar in consign_verify/policy.rego))

{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "cosign.sigstore.dev/attestation/v1",
  "subject": [
    {
      "name": "us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee",
      "digest": {
        "sha256": "a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f"
      }
    }
  ],
  "predicate": {
    "Data": "{ \"projectid\": \"mineral-minutia-820\", \"buildid\": \"ad13230b-9fbd-4074-aa09-4243bc7c7f66\", \"foo\":\"bar\", \"commitsha\": \"c74b95d577555482072a7933df8113e583a4d369\"}",
    "Timestamp": "2023-05-09T03:37:03Z"
  }
}
```

You can also encode in verificaiton of each participants cosign signatures into the code.

This is similar to [binary authorization](https://cloud.google.com/binary-authorization) except that the verification occurs incode using baked in public keys

In this mode, the secure image you're deploying "checks" the hash value for its own image from `/run/container_launcher/attestation_verifier_claims_token` and then use a static (or configured) set of public or KMS keys to verify signatures or attestations predicates are preset.

This is currently not included in this sample but you could modify it using examples [here](https://github.com/salrashid123/cosign_bazel_cloud_build/blob/main/client/main.go)

As mentioned above, each collaborator could also optionally provide the builder a singature for inclusion to the registry.  


For example:

* 1 collaborator-1, -2 and builder creates a image signing key

* 2 collaborator-1, -2 gives the public key for image siginig to the builder

* 3 the deployed code does the following on `func init() {}`:

  ```golang
  const (
    builder_public_key=".."
    collaborator_1_public_key=".."
    collaborator_2_public_key=".."
  )
  var (
      signatures_to_check := []string{ builder_public_key, collaborator_1_public_key, collaborator_2_public_key }
  )
  func init() {
    // verify attestation jwt and extract current image hash by decoding {submods.container.image_reference} from
    // /run/container_launcher/attestation_verifier_claims_token
    imageRef := "..."

    for __, publicKey in range signatures_to_check {
      // verify signatures using each publicKey against imageRef
      // https://github.com/salrashid123/cosign_bazel_cloud_build/blob/main/client/main.go#L127-L190
    }
  }
  ```

* 4 collaborator-1, 2 builder _offline_ sign the image using their private key:
  - [Sign without upload to registry](https://github.com/salrashid123/cosign_bazel_cloud_build/blob/main/README.md#sign-without-upload-to-registry)

* 5 builder _attaches_ all the signatures to the registry
  - [Sign offline and attach](https://github.com/salrashid123/cosign_bazel_cloud_build/blob/main/README.md#sign-offline-and-attach)
  - Alternatively, the builder can provide the signatures as arguments to the TEE containers's startup

* 6 On deployment, the startup init in step 3 will ensure all parties signed image before doing anything

### Software Bill of Materials
  
This repo also demonstrates basic [Software Bill of materials](https://www.cisa.gov/sbom) for:

* application code
* container image

The application code sbom is created as part of the build is _also_ generated using [syft](https://github.com/anchore/syft)  and `goreleaser` and can be found in the `Releases` section of the repo.  The sbom contains all the software used by go application.

The container `sbom` is generated at build time and saved in the container registry.  

>> unfortunately, the `bazel` toolchain does not surface the go libraries used by the application. see

* [syft/1725](https://github.com/anchore/syft/issues/1725)

`kaniko` based builds, however, shows

```bash
$ syft packages    us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f

 ✔ Loaded image            
 ✔ Parsed image            
 ✔ Cataloged packages      [34 packages]

NAME                                                VERSION                             TYPE      
base-files                                          11.1+deb11u7                        deb        
cloud.google.com/go                                 v0.107.0                            go-module  
cloud.google.com/go/compute/metadata                v0.2.3                              go-module  
cloud.google.com/go/iam                             v0.8.0                              go-module  
cloud.google.com/go/kms                             v1.6.0                              go-module  
cloud.google.com/go/logging                         v1.6.1                              go-module  
cloud.google.com/go/longrunning                     v0.4.1                              go-module  
cloud.google.com/go/pubsub                          v1.27.1                             go-module  
github.com/golang-jwt/jwt                           v3.2.2+incompatible                 go-module  
github.com/golang/groupcache                        v0.0.0-20200121045136-8c9f03a8e57e  go-module  
github.com/golang/protobuf                          v1.5.2                              go-module  
github.com/google/go-cmp                            v0.5.9                              go-module  
github.com/googleapis/enterprise-certificate-proxy  v0.2.3                              go-module  
github.com/googleapis/gax-go/v2                     v2.7.0                              go-module  
github.com/gorilla/mux                              v1.8.0                              go-module  
github.com/lestrrat/go-jwx                          v0.9.1                              go-module  
github.com/lestrrat/go-pdebug                       v0.0.0-20180220043741-569c97477ae8  go-module  
github.com/pkg/errors                               v0.9.1                              go-module  
github.com/salrashid123/confidential_space/app      (devel)                             go-module  
go.opencensus.io                                    v0.24.0                             go-module  
golang.org/x/net                                    v0.6.0                              go-module  
golang.org/x/oauth2                                 v0.5.0                              go-module  
golang.org/x/sync                                   v0.1.0                              go-module  
golang.org/x/sys                                    v0.5.0                              go-module  
golang.org/x/text                                   v0.7.0                              go-module  
google.golang.org/api                               v0.110.0                            go-module  
google.golang.org/genproto                          v0.0.0-20230209215440-0dfe4f8abfcc  go-module  
google.golang.org/grpc                              v1.53.0                             go-module  
google.golang.org/protobuf                          v1.28.1                             go-module  
libc6                                               2.31-13+deb11u6                     deb        
libssl1.1                                           1.1.1n-0+deb11u4                    deb        
netbase                                             6.3                                 deb        
openssl                                             1.1.1n-0+deb11u4                    deb        
tzdata                                              2021a-1+deb11u10                    deb       
```

The sboms also include signatures verfiying its authenticity.  

The container image is signed by the same kms based cosing key

#### Download and Verify image sbom:

```bash
# download the imagebom 
$ cosign download sbom --output-file  latest.spdx.download \
      us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f 

$ cosign verify --key /tmp/kms_pub.pem --attachment=sbom   \
        us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f  | jq '.'

Verification for us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee:sha256-a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f.sbom --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
[
  {
    "critical": {
      "identity": {
        "docker-reference": "us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee"
      },
      "image": {
        "docker-manifest-digest": "sha256:d2f9fe2b82a3dcdb550f609af52606aa0a95d9e91feec8e196cbbed729300fa8"
      },
      "type": "cosign container image signature"
    },
    "optional": {
      "commit_sha": "c74b95d577555482072a7933df8113e583a4d369"
    }
  }
]
```

#### Download and Verify application sbom:

For the application, note we're asking for the `type=` field below

```bash
cosign verify-attestation --key /tmp/kms_pub.pem   --type="https://cyclonedx.org/bom/v1.4" \
      us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f  | jq '.'

## note the payload:  thats the full signed software sbom generated as part of cloud build

Verification for us-central1-docker.pkg.dev/mineral-minutia-820/repo1/tee@sha256:a76fd40d851d895f6eee2b047ceaf84fcb06812ef1707dbc9a22e4e74f4cfd1f --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - The signatures were verified against the specified public key
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6Imh0dHBzOi......really long decode as jwt",
  "signatures": [
    {
      "keyid": "",
      "sig": "MEUCID8m9LtTYV7Ag/e2QrYXrxb8AZeN6pCjspkZove+ZyHOAiEAvPViQRThkT2gz6geVIJZ2NU8YZefMmz3ZnF/CY1THAs="
    }
  ]
}
```

#### Local Kaniko build artifiact registry authentication

The following config allows you to use local docker kaniko to push to container registry

```bash
## acquired token is valid for 1 hour by default
token=$(gcloud auth print-access-token)
docker_token=$(echo -n "gclouddockertoken:$token" | base64 | tr -d "\n")

cat > ~/.docker/config_kaniko.json <<- EOM
{
  "auths": {
    "gcr.io": {
      "auth": "$docker_token",
      "email": "not@val.id"
    },
    "us.gcr.io": {
      "auth": "$docker_token",
      "email": "not@val.id"
    },
    "us-central1-docker.pkg.dev": {
      "auth": "$docker_token",
      "email": "not@val.id"
    }
  }
}
EOM

## note the `config_kanklo.json file with the token is passed through to the container
docker run    -v `pwd`:/workspace   -v $HOME/.docker/config_kaniko.json:/kaniko/.docker/config.json:ro  \
             gcr.io/kaniko-project/executor@sha256:034f15e6fe235490e64a4173d02d0a41f61382450c314fffed9b8ca96dff66b2    \
              --dockerfile=Dockerfile --reproducible \
              --destination "us-central1-docker.pkg.dev/$BUILDER_PROJECT_ID/repo1/tee:server"     --context dir:///workspace/
```

#### CNCF Confidential Containers

CNCF's [confidential-containers](https://github.com/confidential-containers) project is a variation of Confidential Space.

For example, the same concepts Confidential Container employs such as attestation, verification and key release shares similar methodologies.

Necessarily, the operator of the infrastructure is critically de-privleged from the workload:

(from [Understanding the Confidential Containers Attestation Flow](https://www.redhat.com/en/blog/understanding-confidential-containers-attestation-flow)):

```
In a typical Kubernetes context, the infrastructure provider (such as a public cloud provider) is not considered a threat agent. It is a trusted actor of a Kubernetes deployment.

In a confidential computing context, that assumption no longer applies and the infrastructure provider is a potential threat agent. Confidential Computing in general, and Confidential Containers in particular, try to protect Kubernetes workload owners from the infrastructure provider. Any software component that belongs to the infrastructure (e.g. the Kubernetes control plane) is untrusted.
```

At face, basic 'level' where Confidential Containers currently operates at is receiving entitlements to pull, decrypt, verify and run a container image that is deemed sensitive.

Confidential Space on the other hand, delegates the ability to pull and run an image back to the Operator but the decryption keys or sensitive key material is done *within* the container is only released after attestation.

With Confidential Space, the attestation service and access control is provided by the Cloud Provider (eg. Google) and not the Operator of the kubernetes cluster (i.,e the owner of the kubernetes cluster or GCP project).

With Confidential Containers, the agent that _begins_ the attestation process is on the Node.  For example, the k8s Node that intends to run a sensitive container image is bootstrapped by a privleged `kata-agent` which inturn provides attestation statements to an external service that releases the decryption keys back to the agent that enables it to pull and run the sensitive image.

Basically, one operates at the ability pull secrets to start a workload container image while other operates after an image is started and acquires secrets via attestation.  Ofcourse Confidential Containers can be extended to surface attestation _into_ the container as well (see `Azure Confidential Containers` below)

* [CNCF Confidential Containers Architecture](https://github.com/confidential-containers/documentation/blob/main/architecture.md)
* [How to use Confidential Containers without confidential hardware](https://www.redhat.com/en/blog/how-use-confidential-containers-without-confidential-hardware)
* [Kata Containers](https://katacontainers.io/)
* [Container Image Encryption & Decryption in the CoCo project](https://medium.com/kata-containers/confidential-containers-and-encrypted-container-images-fc4cdb332dec)
* [OCICrypt Container Image KMS Provider](https://github.com/salrashid123//ocicrypt-kms-keyprovider)

In summary, the basic common objectives are the same but the mechanism and levels at which they operate are different

#### Azure Confidential Containers

[Azure Confidential containers](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers) implements a similar flow to Confidential Space.  It does not seem to be bound to simple enforcement gating the ability to _download_ an image but specifies capabilities to perform key release based on the full container specification and environment at runtime.

It seems the general flow with Azure is to first define a security policy specification which would include the target runtime specification using the [Azure confcom CLI tool](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-tutorial-deploy-confidential-containers-cce-arm#create-an-aci-container-group-arm-template) utility.   Specifically i think using something like [confcom.security_policy.load_policy_from_image_name()](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/azext_confcom/security_policy.py#L664) (see [test_confcom_image.py](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/azext_confcom/tests/latest/test_confcom_image.py)). 

from azure docs:

```
When a security policy gets injected into the ARM Template, the corresponding sha256 hash of the decoded security policy gets printed to the command line. This sha256 hash can be used for verifying the hostdata field of the SEV-SNP Attestation Report and/or used for key release policies using MAA (Microsoft Azure Attestation) or mHSM (managed Hardware Security Module)
```

Given the specification, a final policy hash is generated using and injected into the Azure deploymentTemplate for a [Container Group](https://github.com/Azure/azure-cli-extensions/blob/main/src/confcom/samples/sample-template-output.json#L16)


On deployment, the aggregate hash appears in an attestation statement from within the container provide by a sidecar services (see [Azure Attestation Token](https://learn.microsoft.com/en-us/azure/attestation/basic-concepts#attestation-token) (see [Attestation Token Examples](https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples) ),):

```
Confidential containers on Azure Container Instances provide a sidecar open source container for attestation and secure key release. This sidecar instantiates a web server, which exposes a REST API so that other containers can retrieve a hardware attestation report or a Microsoft Azure Attestation token via the POST method. The sidecar integrates with Azure Key vault for releasing a key to the container group after validation has been completed.
```

There are other capabilities of Azure:

* [Attested TLS](https://github.com/microsoft/confidential-ai/blob/main/inference/README.md#client-setup)
* [Confidential containers on Azure](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-containers)
* [Confidential containers on Azure Container Instances](https://learn.microsoft.com/en-us/azure/container-instances/container-instances-confidential-overview)
* [Azure Container Instances Confidential Hello World](https://github.com/Azure-Samples/aci-confidential-hello-world)
* [Microsoft.ContainerInstance containerGroups](https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?pivots=deployment-language-arm-template)