module github.com/salrashid123/confidential_space/misc/aws-channel-jwt-credential/process

go 1.21

require (
	github.com/google/uuid v1.3.1
	github.com/salrashid123/confidential_space/misc/testtoken v0.0.0
)

require github.com/golang-jwt/jwt/v5 v5.0.0

require github.com/salrashid123/confidential_space/claims v0.0.0-20231103025304-cca1c2218a63 // indirect

replace github.com/salrashid123/confidential_space/misc/testtoken => ../../testtoken
