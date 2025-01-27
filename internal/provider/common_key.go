// Copyright (c) HashiCorp, Inc.

// https://github.com/hashicorp/terraform-provider-tls/blob/main/internal/provider/common_key.go

package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type keyParser func([]byte) (crypto.PrivateKey, error)

var keyParsers = map[PEMPreamble]keyParser{
	PreamblePrivateKeyRSA: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS1PrivateKey(der)
	},
	PreamblePrivateKeyEC: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParseECPrivateKey(der)
	},
	PreamblePrivateKeyPKCS8: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS8PrivateKey(der)
	},
}

func parsePrivateKeyPEM(keyPEMBytes []byte) (crypto.PrivateKey, Algorithm, error) {
	pemBlock, rest := pem.Decode(keyPEMBytes)
	if pemBlock == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block: decoded bytes %d, undecoded %d", len(keyPEMBytes)-len(rest), len(rest))
	}

	// Identify the PEM preamble from the block
	preamble, err := pemBlockToPEMPreamble(pemBlock)
	if err != nil {
		return nil, "", err
	}

	// Identify parser for the given PEM preamble
	parser, ok := keyParsers[preamble]
	if !ok {
		return nil, "", fmt.Errorf("unable to determine parser for PEM preamble: %s", preamble)
	}

	// Parse the specific crypto.PrivateKey from the PEM Block bytes
	prvKey, err := parser(pemBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse private key given PEM preamble '%s': %w", preamble, err)
	}

	// Identify the Algorithm of the crypto.PrivateKey
	algorithm, err := privateKeyToAlgorithm(prvKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to determine key algorithm for private key of type %T: %w", prvKey, err)
	}

	return prvKey, algorithm, nil
}

func privateKeyToAlgorithm(prvKey crypto.PrivateKey) (Algorithm, error) {
	switch prvKey.(type) {
	case rsa.PrivateKey, *rsa.PrivateKey:
		return RSA, nil
	case ecdsa.PrivateKey, *ecdsa.PrivateKey:
		return ECDSA, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return ED25519, nil
	default:
		return "", fmt.Errorf("unsupported private key type: %T", prvKey)
	}
}
