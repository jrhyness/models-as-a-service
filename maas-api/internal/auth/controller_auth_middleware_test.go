package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/opendatahub-io/models-as-a-service/maas-api/internal/logger"
)

func TestControllerAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := logger.Development()

	t.Run("Success_ControllerServiceAccount", func(t *testing.T) {
		// Create a fake Kubernetes client that will return successful TokenReview
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: "system:serviceaccount:opendatahub:maas-controller",
						Groups:   []string{"system:serviceaccounts", "system:authenticated"},
					},
				},
			}, nil
		})

		middleware := ControllerAuthMiddleware(log, fakeClient, "opendatahub")

		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		c.Request = req

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Forbidden_WrongServiceAccount", func(t *testing.T) {
		// Create a fake client that returns a different service account
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: "system:serviceaccount:other-ns:other-sa",
						Groups:   []string{"system:serviceaccounts", "system:authenticated"},
					},
				},
			}, nil
		})

		middleware := ControllerAuthMiddleware(log, fakeClient, "opendatahub")

		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		c.Request = req

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Forbidden_RegularUser", func(t *testing.T) {
		// Create a fake client that returns a regular user (not service account)
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					User: authenticationv1.UserInfo{
						Username: "alice@example.com",
						Groups:   []string{"system:authenticated"},
					},
				},
			}, nil
		})

		middleware := ControllerAuthMiddleware(log, fakeClient, "opendatahub")

		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		c.Request = req

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Unauthorized_MissingToken", func(t *testing.T) {
		fakeClient := fake.NewSimpleClientset()
		middleware := ControllerAuthMiddleware(log, fakeClient, "opendatahub")

		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		c.Request = req

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Unauthorized_InvalidToken", func(t *testing.T) {
		// Create a fake client that returns unauthenticated
		fakeClient := fake.NewSimpleClientset()
		fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
			return true, &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: false,
					Error:         "token is invalid",
				},
			}, nil
		})

		middleware := ControllerAuthMiddleware(log, fakeClient, "opendatahub")

		w := httptest.NewRecorder()
		c, router := gin.CreateTestContext(w)
		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		c.Request = req

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
