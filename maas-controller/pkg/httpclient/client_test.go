package httpclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostAndReadJSON(t *testing.T) {
	// Create test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Read request body
		var reqBody map[string]string
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)
		assert.Equal(t, "test-tenant", reqBody["tenant"])

		// Write response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		resp := map[string]any{
			"revokedCount": 3,
			"message":      "Success",
		}
		err = json.NewEncoder(w).Encode(resp)
		require.NoError(t, err)
	}))
	defer server.Close()

	// Create client with test server's certificate
	client := &Client{
		httpClient: server.Client(),
	}

	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()
		reqBody := map[string]string{"tenant": "test-tenant"}
		var respBody struct {
			RevokedCount int    `json:"revokedCount"`
			Message      string `json:"message"`
		}

		err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
		require.NoError(t, err)
		assert.Equal(t, 3, respBody.RevokedCount)
		assert.Equal(t, "Success", respBody.Message)
	})

	t.Run("InvalidJSON", func(t *testing.T) {
		ctx := context.Background()
		// Channel cannot be marshaled to JSON
		reqBody := make(chan int)
		var respBody map[string]any

		err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal request")
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		reqBody := map[string]string{"tenant": "test"}
		var respBody map[string]any

		err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
		require.Error(t, err)
	})
}

func TestPostAndReadJSON_HTTPErrors(t *testing.T) {
	testCases := []struct {
		name           string
		statusCode     int
		responseBody   string
		expectedErrMsg string
	}{
		{
			name:           "400 Bad Request",
			statusCode:     http.StatusBadRequest,
			responseBody:   `{"error": "missing tenant"}`,
			expectedErrMsg: "HTTP 400",
		},
		{
			name:           "500 Internal Server Error",
			statusCode:     http.StatusInternalServerError,
			responseBody:   `{"error": "database error"}`,
			expectedErrMsg: "HTTP 500",
		},
		{
			name:           "404 Not Found",
			statusCode:     http.StatusNotFound,
			responseBody:   `{"error": "not found"}`,
			expectedErrMsg: "HTTP 404",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write([]byte(tc.responseBody))
			}))
			defer server.Close()

			client := &Client{
				httpClient: server.Client(),
			}

			ctx := context.Background()
			reqBody := map[string]string{"tenant": "test"}
			var respBody map[string]any

			err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErrMsg)
		})
	}
}

func TestPostAndReadJSON_InvalidResponseJSON(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"invalid": json}`)) // Invalid JSON
	}))
	defer server.Close()

	client := &Client{
		httpClient: server.Client(),
	}

	ctx := context.Background()
	reqBody := map[string]string{"tenant": "test"}
	var respBody map[string]any

	err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestClientTimeout(t *testing.T) {
	// Create server that delays response
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	// Create client with very short timeout
	client := &Client{
		httpClient: &http.Client{
			Transport: server.Client().Transport,
			Timeout:   50 * time.Millisecond,
		},
	}

	ctx := context.Background()
	reqBody := map[string]string{"tenant": "test"}
	var respBody map[string]any

	err := client.PostAndReadJSON(ctx, server.URL, reqBody, &respBody)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
}
