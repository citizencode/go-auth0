package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	jwtLib "github.com/golang-jwt/jwt/v4"
)

func NewValidator(uri string) (*RS256, error) {
	jwks, err := fetchJwks(uri)
	if err != nil {
		return nil, err
	}
	return RS256{jwks}, nil
}

type RS256 struct {
	jwks *jwks
}

type JWT struct {
}

func (r RS256) keyFunc(token *jwtLib.Token) (interface{}, error) {
	if token.Method.Alg() != "RS256" {
		return nil, fmt.Errorf("incorrect Alg, expected RS256 got %q", token.Method.Alg())
	}
	kidInterface, ok := token.Header["kid"]
	if !ok {
		return nil, fmt.Errorf("expected header to contain 'kid' key")
	}
	kid := kidInterface.(string)

	var jwkKey jwk
	var found bool
	for _, k := range r.jwks.Keys {
		if k.KeyId == kid {
			jwkKey = k
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("could not find key with matching kid=%q", kid)
	}
	if len(jwkKey.X5CertificateChain) == 0 {
		return nil, fmt.Errorf("x5c field is required")
	}
	// The standard requires that the first certificate is the one that encoded the key.
	cert, err := decodeCertificate(jwkKey.X5CertificateChain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert, %w", err)
	}
	return cert.PublicKey, nil
}

func decodeCertificate(encodedCert string) (*x509.Certificate, error) {
	certPem := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%v\n-----END CERTIFICATE-----\n", encodedCert)
	block, _ := pem.Decode([]byte(certPem))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate, %w", err)
	}
	return cert, nil
}

func (r RS256) JWT(token string) (*jwtLib.Token, error) {
	return jwtLib.Parse(token, jwtLib.Keyfunc(r.keyFunc))
}

func NewRS256(jwksUri string) (*RS256, error) {
	j, err := fetchJwks(jwksUri)
	if err != nil {
		return nil, err
	}
	return &RS256{
		jwks: j,
	}, nil
}
