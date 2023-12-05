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
