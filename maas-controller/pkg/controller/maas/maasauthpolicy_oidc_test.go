/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package maas

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestFetchOIDCConfig_NoModelsAsService(t *testing.T) {
	scheme := runtime.NewScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	reconciler := &MaaSAuthPolicyReconciler{
		Client: client,
		Scheme: scheme,
	}

	config := reconciler.fetchOIDCConfig(context.Background(), logr.Discard())
	assert.Nil(t, config, "should return nil when ModelsAsService doesn't exist")
}

func TestFetchOIDCConfig_NoExternalOIDC(t *testing.T) {
	scheme := runtime.NewScheme()

	// Create ModelsAsService without externalOIDC
	maas := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "opendatahub.io/v1",
			"kind":       "ModelsAsService",
			"metadata": map[string]interface{}{
				"name": "test-maas",
			},
			"spec": map[string]interface{}{
				"otherField": "value",
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(maas).
		Build()

	reconciler := &MaaSAuthPolicyReconciler{
		Client: client,
		Scheme: scheme,
	}

	config := reconciler.fetchOIDCConfig(context.Background(), logr.Discard())
	assert.Nil(t, config, "should return nil when externalOIDC is not configured")
}

func TestFetchOIDCConfig_WithExternalOIDC(t *testing.T) {
	scheme := runtime.NewScheme()

	// Create ModelsAsService with externalOIDC
	maas := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "opendatahub.io/v1",
			"kind":       "ModelsAsService",
			"metadata": map[string]interface{}{
				"name": "test-maas",
			},
			"spec": map[string]interface{}{
				"externalOIDC": map[string]interface{}{
					"issuerUrl": "https://keycloak.example.com/realms/test",
					"clientId":  "test-client",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(maas).
		Build()

	reconciler := &MaaSAuthPolicyReconciler{
		Client: client,
		Scheme: scheme,
	}

	config := reconciler.fetchOIDCConfig(context.Background(), logr.Discard())
	assert.NotNil(t, config, "should return config when externalOIDC is configured")
	assert.Equal(t, "https://keycloak.example.com/realms/test", config.IssuerURL)
	assert.Equal(t, "test-client", config.ClientID)
}

func TestFetchOIDCConfig_EmptyIssuerURL(t *testing.T) {
	scheme := runtime.NewScheme()

	// Create ModelsAsService with empty issuerUrl
	maas := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "opendatahub.io/v1",
			"kind":       "ModelsAsService",
			"metadata": map[string]interface{}{
				"name": "test-maas",
			},
			"spec": map[string]interface{}{
				"externalOIDC": map[string]interface{}{
					"issuerUrl": "",
					"clientId":  "test-client",
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(maas).
		Build()

	reconciler := &MaaSAuthPolicyReconciler{
		Client: client,
		Scheme: scheme,
	}

	config := reconciler.fetchOIDCConfig(context.Background(), logr.Discard())
	assert.Nil(t, config, "should return nil when issuerUrl is empty")
}

func TestCELExpressions_SupportOIDC(t *testing.T) {
	// Test that CEL expressions include OIDC identity fields
	assert.Contains(t, celUserID, "auth.identity.preferred_username",
		"celUserID should check for OIDC preferred_username")
	assert.Contains(t, celUserID, "auth.identity.sub",
		"celUserID should check for OIDC sub claim")
	assert.Contains(t, celUserID, "auth.identity.user.username",
		"celUserID should fall back to K8s user.username")

	assert.Contains(t, celGroups, "auth.identity.groups",
		"celGroups should check for OIDC groups claim")
	assert.Contains(t, celGroups, "auth.identity.user.groups",
		"celGroups should fall back to K8s user.groups")
}

func TestCELExpressions_OrderMatters(t *testing.T) {
	// Verify that OIDC checks come before K8s checks
	// This is important because OIDC and K8s identity structures differ

	// For username: should check preferred_username before user.username
	preferredIdx := findSubstring(celUserID, "preferred_username")
	userUsernameIdx := findSubstring(celUserID, "user.username")
	assert.True(t, preferredIdx >= 0, "should check for preferred_username")
	assert.True(t, userUsernameIdx >= 0, "should check for user.username")
	assert.True(t, preferredIdx < userUsernameIdx,
		"should check preferred_username (OIDC) before user.username (K8s)")

	// For groups: should check auth.identity.groups before auth.identity.user.groups
	identityGroupsIdx := findSubstring(celGroups, "auth.identity.groups")
	userGroupsIdx := findSubstring(celGroups, "auth.identity.user.groups")
	assert.True(t, identityGroupsIdx >= 0, "should check for auth.identity.groups")
	assert.True(t, userGroupsIdx >= 0, "should check for auth.identity.user.groups")
	assert.True(t, identityGroupsIdx < userGroupsIdx,
		"should check auth.identity.groups (OIDC) before auth.identity.user.groups (K8s)")
}

// Helper function to find substring index
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
