package auth

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// MetricsAuthMiddleware protects GET /metrics using Kubernetes authn/authz:
// bearer token TokenReview + SubjectAccessReview on non-resource URL /metrics.
func MetricsAuthMiddleware(log *slog.Logger, kubeClient kubernetes.Interface) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), kubeAPITimeout)
		defer cancel()

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debug("missing or invalid Authorization header for metrics")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "Missing or invalid bearer token",
			})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: token}}
		result, err := kubeClient.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
		if err != nil {
			log.Error("metrics TokenReview failed", "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Token validation error",
			})
			c.Abort()
			return
		}

		if !result.Status.Authenticated {
			log.Debug("metrics token not authenticated", "error", result.Status.Error)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Invalid token",
			})
			c.Abort()
			return
		}

		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   result.Status.User.Username,
				Groups: result.Status.User.Groups,
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/metrics",
					Verb: "get",
				},
			},
		}

		sarResult, sarErr := kubeClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
		if sarErr != nil {
			log.Error("metrics SubjectAccessReview failed", "error", sarErr)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization check failed",
				"details": "Unable to verify metrics access",
			})
			c.Abort()
			return
		}

		if !sarResult.Status.Allowed {
			log.Debug("metrics access denied", "reason", sarResult.Status.Reason)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"details": "User is not authorized to access /metrics",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
