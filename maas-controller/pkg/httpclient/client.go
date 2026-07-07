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
	ServiceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	ServiceCAPath           = "/var/run/secrets/openshift-service-ca/service-ca.crt"
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type Client struct {
	httpClient *http.Client
	token      string // Service account token for authentication
}

// NewInClusterClient creates an HTTP client configured for in-cluster communication with TLS.
// The client loads both the cluster CA and OpenShift service CA certificates for TLS verification.
// Internal maas-api services use OpenShift service serving certificates.
func NewInClusterClient(timeout time.Duration) (*Client, error) {
	caCertPool := x509.NewCertPool()

	// Load cluster CA certificate
	clusterCA, err := os.ReadFile(ServiceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster CA: %w", err)
	}
	if !caCertPool.AppendCertsFromPEM(clusterCA) {
		return nil, errors.New("failed to parse cluster CA certificate")
	}

	// Load OpenShift service CA certificate for maas-api service certificates
	serviceCA, err := os.ReadFile(ServiceCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load service CA: %w", err)
	}
	if !caCertPool.AppendCertsFromPEM(serviceCA) {
		return nil, errors.New("failed to parse service CA certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:    caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	// Load service account token for authentication with maas-api internal endpoints
	token, err := os.ReadFile(ServiceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load service account token: %w", err)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
		token: string(token),
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
	// Add service account token for authentication with maas-api internal endpoints
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Limit response body size to prevent memory exhaustion (1MB should be plenty for our JSON responses)
	const maxResponseSize = 1 << 20 // 1MB
	limitedBody := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(limitedBody)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(limitedBody).Decode(respBody); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
