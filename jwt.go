package jwt

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"

	jwtLib "github.com/golang-jwt/jwt/v4"
)

// MapClaims is a claims type that uses the map[string]interface{} for JSON decoding.
// This is the default claims type if you don't supply one
type MapClaims = jwtLib.MapClaims

func NewRS256(uri string) (*RS256, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	var jwks *jwks
	if u.Scheme != "file" {
		jwks, err = fetchJwks(uri)
		if err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(u.Path)
		if err != nil {
			return nil, fmt.Errorf("could not open jwks file, %q, %w", u.Path, err)
		}
		rawJwks, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("could not read jwks file, %q, %w", u.Path, err)
		}
		jwks, err = parseJwks(rawJwks)
		if err != nil {
			return nil, fmt.Errorf("could not parse jwks file %q, %w", u.Path, err)
		}
	}
	return &RS256{jwks}, nil
}

type RS256 struct {
	jwks *jwks
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
