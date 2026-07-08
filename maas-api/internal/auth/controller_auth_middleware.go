package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

// ControllerAuthMiddleware validates that the request is from the maas-controller service account.
// This middleware should be used on internal endpoints that should only be callable by the controller.
func ControllerAuthMiddleware(log *logger.Logger, kubeClient kubernetes.Interface, controllerNamespace string) gin.HandlerFunc {
	expectedUsername := fmt.Sprintf("system:serviceaccount:%s:maas-controller", controllerNamespace)

	return func(c *gin.Context) {
		// Set a hard timeout for Kubernetes API calls to prevent hangs
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()

		// Step 1: Extract and validate bearer token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debug("Missing or invalid Authorization header for controller endpoint")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "Missing or invalid bearer token",
			})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Step 2: Validate token via TokenReview and extract user identity
		tr := &authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{Token: token},
		}
		result, err := kubeClient.AuthenticationV1().TokenReviews().Create(
			ctx, tr, metav1.CreateOptions{},
		)

		if err != nil {
			log.Error("TokenReview failed for controller endpoint", "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Token validation error",
			})
			c.Abort()
			return
		}

		if !result.Status.Authenticated {
			log.Debug("Token not authenticated for controller endpoint",
				"error", result.Status.Error)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Invalid token",
			})
			c.Abort()
			return
		}

		username := result.Status.User.Username

		// Step 3: Verify the caller is the maas-controller service account
		if username != expectedUsername {
			log.Warn("Unauthorized access attempt to controller-only endpoint",
				"username", username,
				"expected", expectedUsername)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"details": "This endpoint is only accessible by the maas-controller",
			})
			c.Abort()
			return
		}

		log.Debug("Controller authentication successful", "username", username)

		// Token valid and caller is maas-controller - proceed
		c.Next()
	}
}
