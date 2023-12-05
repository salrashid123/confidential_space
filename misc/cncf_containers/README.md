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

