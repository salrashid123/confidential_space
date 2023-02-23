package main

import "github.com/golang-jwt/jwt"

type VersionClaims struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

type PlatformClaims struct {
	HardwareTechnology string `json:"hardware_technology,omitempty"`
}

type ContainerClaims struct {
	ImageReference string            `json:"image_reference"`
	ImageDigest    string            `json:"image_digest"`
	RestartPolicy  string            `json:"restart_policy"`
	ImageID        string            `json:"image_id"`
	EnvOverride    map[string]string `json:"env_override"`
	CmdOverride    []string          `json:"cmd_override"`
	Env            map[string]string `json:"env"`
	Args           []string          `json:"args"`
}

type GCEClaims struct {
	Zone          string `json:"zone,omitempty"`
	ProjectID     string `json:"project_id,omitempty"`
	ProjectNumber uint64 `json:"project_number,string,omitempty"`
	InstanceName  string `json:"instance_name,omitempty"`
	InstanceID    uint64 `json:"instance_id,string,omitempty"`
}

type TEEClaims struct {
	Version   VersionClaims   `json:"version"`
	Platform  PlatformClaims  `json:"platform"`
	Container ContainerClaims `json:"container"`
	GCE       GCEClaims       `json:"gce"`
	Emails    []string        `json:"emails,omitempty"`
}

type ConfidentialSpaceClaims struct {
	SupportAttributes string `json:"support_attributes"`
}

type SubmodClaims struct {
	Container         ContainerClaims         `json:"container"`
	GCE               GCEClaims               `json:"gce"`
	ConfidentialSpace ConfidentialSpaceClaims `json:"confidential_space"`
}

type Claims struct {
	jwt.StandardClaims

	Tee                   TEEClaims    `json:"tee"`
	EATNonce              string       `json:"eat_nonce,omitempty"`
	Secboot               bool         `json:"secboot"`
	OEMID                 uint64       `json:"oemid"`
	HardwareModel         string       `json:"hwmodel"`
	SoftwareName          string       `json:"swname"`
	SoftwareVersion       string       `json:"swversion"`
	Dbgstat               string       `json:"dbgstat"`
	GoogleServiceAccounts []string     `json:"google_service_accounts"`
	Submods               SubmodClaims `json:"submods"`
}
