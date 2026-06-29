package tenant

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
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

// TenantInfo represents the tenant and gateway metadata response.
type TenantInfo struct {
	Tenant  TenantMetadata  `json:"tenant"`
	Gateway GatewayMetadata `json:"gateway"`
}

// TenantMetadata contains tenant identification.
type TenantMetadata struct {
	Name string `json:"name"`
}

// GatewayMetadata contains gateway connection details.
type GatewayMetadata struct {
	Name         string             `json:"name"`
	Namespace    string             `json:"namespace"`
	ExternalHost string             `json:"externalHost"`
	ExternalURL  string             `json:"externalUrl"`
	Protocol     string             `json:"protocol"`
	Port         int64              `json:"port"`
	Listeners    []ListenerMetadata `json:"listeners,omitempty"`
}

// ListenerMetadata contains individual listener details.
type ListenerMetadata struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Port     int64  `json:"port"`
	Protocol string `json:"protocol"`
}

// GetTenantInfo returns tenant name and gateway connection metadata.
// GET /v1/tenant
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
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Gateway not found",
			"details": fmt.Sprintf("Gateway %s not found in namespace %s", h.gatewayName, h.gatewayNamespace),
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

	response := TenantInfo{
		Tenant: TenantMetadata{
			Name: h.tenantName,
		},
		Gateway: *gatewayMetadata,
	}

	c.JSON(http.StatusOK, response)
}

// extractGatewayMetadata extracts connection metadata from Gateway status.
// It attempts to find the external hostname from OpenShift Routes first,
// falling back to Gateway status if no Route is found.
func (h *Handler) extractGatewayMetadata(ctx context.Context, gateway map[string]interface{}) (*GatewayMetadata, error) {
	// Extract status
	status, ok := gateway["status"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("gateway status not found")
	}

	// Extract listeners from status
	listenersRaw, ok := status["listeners"].([]interface{})
	if !ok || len(listenersRaw) == 0 {
		return nil, fmt.Errorf("gateway has no listeners in status")
	}

	var listeners []ListenerMetadata
	var primaryListener *ListenerMetadata

	for _, l := range listenersRaw {
		listener, ok := l.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := listener["name"].(string)

		// Get attached routes count to determine if listener is ready
		attachedRoutes, _ := listener["attachedRoutes"].(int64)
		if attachedRoutes == 0 {
			// Skip listeners with no attached routes
			continue
		}

		// Extract hostname from listener status
		hostname := ""
		if hostnameVal, ok := listener["hostname"].(string); ok {
			hostname = hostnameVal
		}

		// Extract port from listener status
		port := int64(443) // default
		if portVal, ok := listener["port"].(int64); ok {
			port = portVal
		}

		// Extract protocol
		protocol := "HTTPS"
		if protocolVal, ok := listener["protocol"].(string); ok {
			protocol = protocolVal
		}

		listenerMeta := ListenerMetadata{
			Name:     name,
			Hostname: hostname,
			Port:     port,
			Protocol: protocol,
		}

		listeners = append(listeners, listenerMeta)

		// Use first HTTPS/TLS listener as primary
		if primaryListener == nil && (protocol == "HTTPS" || protocol == "TLS") {
			primaryListener = &listenerMeta
		}
	}

	if primaryListener == nil && len(listeners) > 0 {
		// Fallback to first listener if no HTTPS/TLS found
		primaryListener = &listeners[0]
	}

	if primaryListener == nil {
		return nil, fmt.Errorf("gateway has no ready listeners")
	}

	// Try to find external hostname from OpenShift Route (preferred for external access)
	externalHost := h.findRouteHostname(ctx)

	// Fallback: try hostname from primary listener
	if externalHost == "" {
		externalHost = primaryListener.Hostname
	}

	// Fallback: try status.addresses
	if externalHost == "" {
		if addresses, ok := status["addresses"].([]interface{}); ok && len(addresses) > 0 {
			if addr, ok := addresses[0].(map[string]interface{}); ok {
				if value, ok := addr["value"].(string); ok {
					externalHost = value
				}
			}
		}
	}

	if externalHost == "" {
		return nil, fmt.Errorf("could not determine external hostname from gateway")
	}

	// Build external URL
	scheme := "https"
	if primaryListener.Protocol == "HTTP" {
		scheme = "http"
	}

	externalURL := fmt.Sprintf("%s://%s", scheme, externalHost)
	// Include port if non-standard
	if (scheme == "https" && primaryListener.Port != 443) || (scheme == "http" && primaryListener.Port != 80) {
		externalURL = fmt.Sprintf("%s:%d", externalURL, primaryListener.Port)
	}

	return &GatewayMetadata{
		Name:         h.gatewayName,
		Namespace:    h.gatewayNamespace,
		ExternalHost: externalHost,
		ExternalURL:  externalURL,
		Protocol:     scheme,
		Port:         primaryListener.Port,
		Listeners:    listeners,
	}, nil
}

// findRouteHostname attempts to find the external hostname from OpenShift Routes
// that reference this Gateway. Returns empty string if no Route is found.
func (h *Handler) findRouteHostname(ctx context.Context) string {
	// Skip if dynamic client is not available (e.g., in unit tests)
	if h.dynamicClient == nil {
		return ""
	}

	// OpenShift Route GVR
	routeGVR := schema.GroupVersionResource{
		Group:    "route.openshift.io",
		Version:  "v1",
		Resource: "routes",
	}

	// List Routes in the Gateway's namespace
	routes, err := h.dynamicClient.Resource(routeGVR).Namespace(h.gatewayNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		// Routes may not exist (non-OpenShift cluster) or no RBAC - not an error
		h.log.Debug("Could not list Routes (may not be OpenShift)", "error", err)
		return ""
	}

	// Find Route that references this Gateway
	gatewayServiceName := fmt.Sprintf("%s-openshift-default", h.gatewayName)

	for _, item := range routes.Items {
		spec, ok := item.Object["spec"].(map[string]interface{})
		if !ok {
			continue
		}

		to, ok := spec["to"].(map[string]interface{})
		if !ok {
			continue
		}

		// Check if Route targets the Gateway Service
		serviceName, ok := to["name"].(string)
		if !ok || serviceName != gatewayServiceName {
			continue
		}

		// Extract hostname from Route spec
		if host, ok := spec["host"].(string); ok && host != "" {
			h.log.Debug("Found external hostname from Route",
				"route", item.GetName(),
				"hostname", host)
			return host
		}
	}

	return ""
}
