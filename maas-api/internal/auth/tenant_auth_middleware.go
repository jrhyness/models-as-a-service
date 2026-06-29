package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

// TenantAuthMiddleware validates bearer tokens via TokenReview and checks tenant access via SubjectAccessReview.
// It verifies that the caller has permission to GET the AITenant CR for this maas-api instance.
func TenantAuthMiddleware(log *logger.Logger, kubeClient kubernetes.Interface, aitenantNamespace, aitenantName string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Step 1: Extract and validate bearer token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Debug("Missing or invalid Authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication required",
				"details": "Missing or invalid bearer token",
			})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Step 2: Validate token via TokenReview and extract user identity
		tr := &authenticationv1.TokenReview{
			Spec: authenticationv1.TokenReviewSpec{Token: token},
		}
		result, err := kubeClient.AuthenticationV1().TokenReviews().Create(
			c.Request.Context(), tr, metav1.CreateOptions{},
		)

		if err != nil {
			log.Error("TokenReview failed", "error", err)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Token validation error",
			})
			c.Abort()
			return
		}

		if !result.Status.Authenticated {
			log.Debug("Token not authenticated",
				"error", result.Status.Error)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Authentication failed",
				"details": "Invalid token",
			})
			c.Abort()
			return
		}

		username := result.Status.User.Username
		groups := result.Status.User.Groups

		log.Debug("Token authenticated", "username", username, "groups", groups)

		// Step 3: Check tenant access via SubjectAccessReview
		// Verify caller has GET permission on the AITenant CR
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User:   username,
				Groups: groups,
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: aitenantNamespace,
					Group:     "maas.opendatahub.io",
					Resource:  "aitenants",
					Verb:      "get",
					Name:      aitenantName,
				},
			},
		}

		sarResult, err := kubeClient.AuthorizationV1().SubjectAccessReviews().Create(
			c.Request.Context(), sar, metav1.CreateOptions{},
		)

		if err != nil {
			log.Error("SubjectAccessReview failed", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "Authorization check failed",
				"details": "Unable to verify tenant access",
			})
			c.Abort()
			return
		}

		if !sarResult.Status.Allowed {
			log.Debug("Access denied to AITenant",
				"username", username,
				"aitenantName", aitenantName,
				"aitenantNamespace", aitenantNamespace,
				"reason", sarResult.Status.Reason)
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "Insufficient permissions",
				"details": "User does not have permission to access this tenant",
			})
			c.Abort()
			return
		}

		log.Debug("Tenant access granted",
			"username", username,
			"aitenantName", aitenantName)

		// Token valid and user has tenant access - proceed
		c.Next()
	}
}
