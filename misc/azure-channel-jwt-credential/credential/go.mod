module github.com/salrashid123/confidential_space/misc/azure-channel-jwt-credential/credential

go 1.21

require (
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.9.0
	github.com/golang-jwt/jwt/v5 v5.0.0
	github.com/salrashid123/confidential_space/misc/testtoken v0.0.0
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/lestrrat/go-jwx v0.9.1 // indirect
	github.com/lestrrat/go-pdebug v0.0.0-20180220043741-569c97477ae8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/salrashid123/confidential_space/claims v0.0.0-20231113123744-44f929093c61 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/text v0.13.0 // indirect
)

replace github.com/salrashid123/confidential_space/misc/testtoken => ../../testtoken
