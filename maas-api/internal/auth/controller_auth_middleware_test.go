package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/auth"
	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

// Helper to reduce test boilerplate.
func setupMiddlewareTest(middleware gin.HandlerFunc) (*httptest.ResponseRecorder, *gin.Engine) {
	w := httptest.NewRecorder()
	_, router := gin.CreateTestContext(w)
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	return w, router
}

func TestControllerAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.Development()

	t.Run("Success_ControllerServiceAccount", func(t *testing.T) {
		// Create a fake Kubernetes client that will return successful TokenReview
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:opendatahub:maas-controller",
						Groups:   []string{"system:serviceaccounts", "system:authenticated"},
					},
				},
			}, nil
		})

		middleware := auth.ControllerAuthMiddleware(log, fakeClient, "opendatahub")
		w, router := setupMiddlewareTest(middleware)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Forbidden_WrongServiceAccount", func(t *testing.T) {
		// Create a fake client that returns a different service account
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "system:serviceaccount:other-ns:other-sa",
						Groups:   []string{"system:serviceaccounts", "system:authenticated"},
					},
				},
			}, nil
		})

		middleware := auth.ControllerAuthMiddleware(log, fakeClient, "opendatahub")
		w, router := setupMiddlewareTest(middleware)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Forbidden_RegularUser", func(t *testing.T) {
		// Create a fake client that returns a regular user (not service account)
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: true,
					User: authv1.UserInfo{
						Username: "alice@example.com",
						Groups:   []string{"system:authenticated"},
					},
				},
			}, nil
		})

		middleware := auth.ControllerAuthMiddleware(log, fakeClient, "opendatahub")
		w, router := setupMiddlewareTest(middleware)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Unauthorized_MissingToken", func(t *testing.T) {
		fakeClient := fake.NewSimpleClientset()
		middleware := auth.ControllerAuthMiddleware(log, fakeClient, "opendatahub")
		w, router := setupMiddlewareTest(middleware)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Unauthorized_InvalidToken", func(t *testing.T) {
		// Create a fake client that returns unauthenticated
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authv1.TokenReview{
				Status: authv1.TokenReviewStatus{
					Authenticated: false,
					Error:         "token is invalid",
				},
			}, nil
		})

		middleware := auth.ControllerAuthMiddleware(log, fakeClient, "opendatahub")
		w, router := setupMiddlewareTest(middleware)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
