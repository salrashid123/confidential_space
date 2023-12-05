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