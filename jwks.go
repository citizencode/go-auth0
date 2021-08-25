package jwt

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

// as defined by https://datatracker.ietf.org/doc/html/rfc7517.
type jwk struct {
	KeyType                 string   `json:"kty"`
	Use                     string   `json:"use"`
	KeyOperations           string   `json:"key_ops"`
	Algorithm               string   `json:"alg"`
	KeyId                   string   `json:"kid"`
	X5URL                   string   `json:"x5u"`
	X5CertificateChain      []string `json:"x5c"`
	X5CertificateThumbprint string   `json:"x5t"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func parseJwks(encodedJson []byte) (*jwks, error) {
	js := &jwks{}
	if err := json.Unmarshal(encodedJson, js); err != nil {
		return nil, fmt.Errorf("could not parse jwks, %w", err)
	}
	return js, nil
}

func fetchJwks(uri string) (*jwks, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch jwks at %q, %w", uri, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read jwks body, %w", err)
	}
	return parseJwks(body)
}
