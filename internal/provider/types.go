// https://github.com/hashicorp/terraform-provider-tls/blob/main/internal/provider/types.go

package provider

import (
	"encoding/pem"
	"fmt"
)

// Algorithm represents a type of private key algorithm.
type Algorithm string

const (
	RSA     Algorithm = "RSA"
	ECDSA   Algorithm = "ECDSA"
	ED25519 Algorithm = "ED25519"
)

func (a Algorithm) String() string {
	return string(a)
}

// ECDSACurve represents a type of ECDSA elliptic curve.
type ECDSACurve string

const (
	P224 ECDSACurve = "P224"
	P256 ECDSACurve = "P256"
	P384 ECDSACurve = "P384"
	P521 ECDSACurve = "P521"
)

func (e ECDSACurve) String() string {
	return string(e)
}

// PEMPreamble represents the heading used in a PEM-formatted for the "encapsulation boundaries",
// that is used to delimit the "encapsulated text portion" of cryptographic documents.
//
// See https://datatracker.ietf.org/doc/html/rfc1421 and https://datatracker.ietf.org/doc/html/rfc7468.
type PEMPreamble string

const (
	PreamblePublicKey PEMPreamble = "PUBLIC KEY"

	PreamblePrivateKeyPKCS8   PEMPreamble = "PRIVATE KEY"
	PreamblePrivateKeyRSA     PEMPreamble = "RSA PRIVATE KEY"
	PreamblePrivateKeyEC      PEMPreamble = "EC PRIVATE KEY"
	PreamblePrivateKeyOpenSSH PEMPreamble = "OPENSSH PRIVATE KEY"

	PreambleCertificate        PEMPreamble = "CERTIFICATE"
	PreambleCertificateRequest PEMPreamble = "CERTIFICATE REQUEST"
)

func (p PEMPreamble) String() string {
	return string(p)
}

// pemBlockToPEMPreamble takes a pem.Block and returns the related PEMPreamble, if supported.
func pemBlockToPEMPreamble(block *pem.Block) (PEMPreamble, error) {
	switch block.Type {
	case PreamblePublicKey.String():
		return PreamblePublicKey, nil
	case PreamblePrivateKeyPKCS8.String():
		return PreamblePrivateKeyPKCS8, nil
	case PreamblePrivateKeyRSA.String():
		return PreamblePrivateKeyRSA, nil
	case PreamblePrivateKeyEC.String():
		return PreamblePrivateKeyEC, nil
	case PreambleCertificate.String():
		return PreambleCertificate, nil
	case PreambleCertificateRequest.String():
		return PreambleCertificateRequest, nil
	default:
		return "", fmt.Errorf("unsupported PEM preamble/type: %s", block.Type)
	}
}

// ProxyScheme represents url schemes supported when providing proxy configuration to this provider.
type ProxyScheme string

const (
	HTTPProxy   ProxyScheme = "http"
	HTTPSProxy  ProxyScheme = "https"
	SOCKS5Proxy ProxyScheme = "socks5"
)

func (p ProxyScheme) String() string {
	return string(p)
}

// URLScheme represents url schemes supported by resources and data-sources of this provider.
type URLScheme string

const (
	HTTPSScheme URLScheme = "https"
	TLSScheme   URLScheme = "tls"
)

func (p URLScheme) String() string {
	return string(p)
}
