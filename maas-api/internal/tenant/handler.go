package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

// Handler handles /v1/tenant endpoint requests.
type Handler struct {
	log              *logger.Logger
	dynamicClient    dynamic.Interface
	tenantName       string
	gatewayName      string
	gatewayNamespace string
}

// NewHandler creates a new tenant handler.
func NewHandler(log *logger.Logger, dynamicClient dynamic.Interface, tenantName, gatewayName, gatewayNamespace string) *Handler {
	return &Handler{
		log:              log,
		dynamicClient:    dynamicClient,
		tenantName:       tenantName,
		gatewayName:      gatewayName,
		gatewayNamespace: gatewayNamespace,
	}
}

// TenantsResponse represents the response for GET /v1/tenants.
// For 3.5, returns a single-element array containing this instance's tenant.
type TenantsResponse struct {
	Tenants []TenantInfo `json:"tenants"`
}

// TenantInfo contains tenant identification and gateway metadata.
type TenantInfo struct {
	Name    string          `json:"name"`
	Gateway GatewayMetadata `json:"gateway"`
}

// GatewayMetadata contains gateway connection details.
type GatewayMetadata struct {
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	Protocol    string `json:"protocol"`
	ExternalURL string `json:"externalUrl"`
	Port        int64  `json:"port"`
}

// GetTenantInfo returns tenant name and gateway connection metadata.
// GET /v1/tenants.
func (h *Handler) GetTenantInfo(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// Fetch Gateway resource
	gatewayGVR := schema.GroupVersionResource{
		Group:    "gateway.networking.k8s.io",
		Version:  "v1",
		Resource: "gateways",
	}

	gateway, err := h.dynamicClient.Resource(gatewayGVR).Namespace(h.gatewayNamespace).Get(ctx, h.gatewayName, metav1.GetOptions{})
	if err != nil {
		h.log.Error("Failed to fetch Gateway",
			"gatewayName", h.gatewayName,
			"gatewayNamespace", h.gatewayNamespace,
			"error", err)

		// Distinguish NotFound from other Kubernetes API errors
		if apierrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{
				"error":   "Gateway not found",
				"details": fmt.Sprintf("Gateway %s not found in namespace %s", h.gatewayName, h.gatewayNamespace),
			})
			return
		}

		// RBAC, timeout, or apiserver issues
		statusCode := http.StatusInternalServerError
		if apierrors.IsForbidden(err) {
			statusCode = http.StatusForbidden
		} else if apierrors.IsTimeout(err) {
			statusCode = http.StatusGatewayTimeout
		}

		c.JSON(statusCode, gin.H{
			"error":   "Failed to fetch Gateway",
			"details": "Unable to query Gateway resource",
		})
		return
	}

	// Extract gateway metadata
	gatewayMetadata, err := h.extractGatewayMetadata(ctx, gateway.Object)
	if err != nil {
		h.log.Error("Failed to extract gateway metadata", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to resolve gateway",
			"details": "Unable to determine external hostname from Gateway status",
		})
		return
	}

	response := TenantsResponse{
		Tenants: []TenantInfo{
			{
				Name:    h.tenantName,
				Gateway: *gatewayMetadata,
			},
		},
	}

	c.JSON(http.StatusOK, response)
}

// extractGatewayMetadata extracts connection metadata from Gateway status.
// Uses Gateway status.addresses and status.listeners to determine external hostname.
func (h *Handler) extractGatewayMetadata(ctx context.Context, gateway map[string]any) (*GatewayMetadata, error) {
	// Extract status
	status, ok := gateway["status"].(map[string]any)
	if !ok {
		return nil, errors.New("gateway status not found")
	}

	// Extract listeners from status to get port and protocol
	listenersRaw, ok := status["listeners"].([]any)
	if !ok || len(listenersRaw) == 0 {
		return nil, errors.New("gateway has no listeners in status")
	}
	// Find first ready listener (has attached routes)
	var port int64 = 443   // default
	var protocol = "HTTPS" // default
	var hostname string

	for _, l := range listenersRaw {
		listener, ok := l.(map[string]any)
		if !ok {
			continue
		}

		// Get attached routes count to determine if listener is ready
		attachedRoutes, _ := listener["attachedRoutes"].(int64)
		if attachedRoutes == 0 {
			continue
		}

		// Extract port
		if portVal, ok := listener["port"].(int64); ok {
			port = portVal
		}

		// Extract protocol
		if protocolVal, ok := listener["protocol"].(string); ok {
			protocol = protocolVal
		}

		// Extract hostname from listener
		if hostnameVal, ok := listener["hostname"].(string); ok {
			hostname = hostnameVal
		}

		// Use first ready listener
		break
	}

	// Get external hostname from Gateway status
	externalHost := hostname

	// Fallback: try status.addresses (set by Gateway controller with external hostname)
	if externalHost == "" {
		if addresses, ok := status["addresses"].([]any); ok && len(addresses) > 0 {
			if addr, ok := addresses[0].(map[string]any); ok {
				if value, ok := addr["value"].(string); ok {
					externalHost = value
				}
			}
		}
	}

	if externalHost == "" {
		return nil, errors.New("could not determine external hostname from gateway")
	}

	// Build external URL
	scheme := "https"
	if protocol == "HTTP" {
		scheme = "http"
	}

	externalURL := fmt.Sprintf("%s://%s", scheme, externalHost)
	// Include port if non-standard
	if (scheme == "https" && port != 443) || (scheme == "http" && port != 80) {
		externalURL = fmt.Sprintf("%s:%d", externalURL, port)
	}

	return &GatewayMetadata{
		Name:        h.gatewayName,
		Namespace:   h.gatewayNamespace,
		Protocol:    scheme,
		ExternalURL: externalURL,
		Port:        port,
	}, nil
}

