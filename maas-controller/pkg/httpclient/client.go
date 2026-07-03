package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	ServiceAccountCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type Client struct {
	httpClient *http.Client
}

// NewInClusterClient creates an HTTP client configured for in-cluster communication with TLS.
// The client loads the cluster CA certificate for TLS verification but does not include
// authentication tokens (internal endpoints are network-restricted).
func NewInClusterClient(timeout time.Duration) (*Client, error) {
	// Load cluster CA certificate for TLS verification
	caCert, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster CA: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse cluster CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

// PostAndReadJSON sends a POST request with JSON body and decodes the JSON response.
// Returns error if HTTP status is not 2xx or if JSON encoding/decoding fails.
func (c *Client) PostAndReadJSON(ctx context.Context, url string, reqBody any, respBody any) error {
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
