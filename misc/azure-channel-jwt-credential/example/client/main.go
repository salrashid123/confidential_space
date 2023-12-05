package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	ek "github.com/salrashid123/confidential_space/misc/azure-channel-jwt-credential/credential"
)

const (
	containerName = "mineral-minutia"
	url           = "https://mineralminutia.blob.core.windows.net/"
)

var ()

func main() {

	flag.Parse()

	creds, err := ek.NewEKMAZCredentials(&ek.EKMAZCredentialOptions{
		// ClientID: "cffeaee2-5617-4784-8a4b-b647efd676d2",
		// TenantID: "45243fbe-b73f-4f7d-8213-a104a99e228e",

		STSEndpoint:     "https://server.domain.com:8081/token",
		STSEndpointHost: "localhost:8081",
		STSSNI:          "server.domain.com",
		Audience:        "https://server.domain.com",

		// Scope:      "https://storage.azure.com/.default",
		UseMTLS:    true,
		TrustCA:    "certs/tls-ca-chain.pem",
		ClientCert: "certs/client-svc.crt",
		ClientKey:  "certs/client-svc.key",
	})
	if err != nil {
		fmt.Printf("Error creating credential" + err.Error())
		os.Exit(1)
	}

	client, err := azblob.NewClient(url, creds, nil)
	if err != nil {
		fmt.Printf("Error creating client: " + err.Error())
		os.Exit(1)
	}
	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{})
	fmt.Println("Objects:")
	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		if err != nil {
			fmt.Printf("Error iterating objects " + err.Error())
			os.Exit(1)
		}
		for _, blob := range resp.Segment.BlobItems {
			fmt.Println(*blob.Name)
		}
	}

	// -----

	subscriptionID := "450b3122-bc25-49b7-86be-7dc86269a2e4"
	resourceGroup := "rg1"
	vmName := "vm1"
	armclient, err := armcompute.NewVirtualMachinesClient(subscriptionID, creds, nil)
	if err != nil {
		fmt.Printf("Invalid NewVirtualMachinesClient client error: " + err.Error())
		os.Exit(1)
	}
	v, err := armclient.Get(context.Background(), resourceGroup, vmName, nil)
	if err != nil {
		fmt.Printf("Error getting vm: " + err.Error())
		os.Exit(1)
	}
	fmt.Printf("VM %s\n", *v.ID)
}
