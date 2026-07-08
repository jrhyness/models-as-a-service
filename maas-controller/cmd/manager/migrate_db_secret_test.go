package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConvertToFQDNConnectionURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		namespace string
		want      string
	}{
		{
			name:      "simple hostname with port",
			url:       "postgresql://user:pass@postgres:5432/db",
			namespace: "opendatahub",
			want:      "postgresql://user:pass@postgres.opendatahub.svc.cluster.local:5432/db",
		},
		{
			name:      "hostname without port",
			url:       "postgresql://user:pass@postgres/db",
			namespace: "redhat-ods-applications",
			want:      "postgresql://user:pass@postgres.redhat-ods-applications.svc.cluster.local/db",
		},
		{
			name:      "already FQDN - no change",
			url:       "postgresql://user:pass@postgres.opendatahub.svc.cluster.local:5432/db",
			namespace: "opendatahub",
			want:      "postgresql://user:pass@postgres.opendatahub.svc.cluster.local:5432/db",
		},
		{
			name:      "hostname with query params",
			url:       "postgresql://user:pass@postgres:5432/db?sslmode=require",
			namespace: "opendatahub",
			want:      "postgresql://user:pass@postgres.opendatahub.svc.cluster.local:5432/db?sslmode=require",
		},
		{
			name:      "external FQDN hostname",
			url:       "postgresql://user:pass@db.example.com:5432/db",
			namespace: "opendatahub",
			want:      "postgresql://user:pass@db.example.com:5432/db",
		},
		{
			name:      "no credentials",
			url:       "postgresql://postgres:5432/db",
			namespace: "opendatahub",
			want:      "postgresql://postgres.opendatahub.svc.cluster.local:5432/db", // Now properly parsed and converted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertToFQDNConnectionURL(tt.url, tt.namespace)
			if got != tt.want {
				t.Errorf("convertToFQDNConnectionURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaskConnectionURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "with password",
			url:  "postgresql://user:password@host:5432/db",
			want: "postgresql://user:xxxxx@host:5432/db", // url.Redacted() uses xxxxx
		},
		{
			name: "no password",
			url:  "postgresql://user@host:5432/db",
			want: "postgresql://user@host:5432/db",
		},
		{
			name: "no credentials",
			url:  "postgresql://host:5432/db",
			want: "postgresql://host:5432/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskConnectionURL(tt.url)
			if got != tt.want {
				t.Errorf("maskConnectionURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateMaaSDBSecretToInfraNamespace(t *testing.T) {
	const (
		secretName      = "maas-db-config" //nolint:gosec // secret name reference, not a credential
		secretKey       = "DB_CONNECTION_URL"
		controllerNs    = "opendatahub"
		infraNs         = "odh-ai-gateway-infra"
		originalConnURL = "postgresql://maas:password@postgres:5432/maas"
		expectedFQDN    = "postgresql://maas:password@postgres.opendatahub.svc.cluster.local:5432/maas"
	)

	tests := []struct {
		name                string
		setupSecrets        func(*fake.Clientset)
		controllerNs        string
		infraNs             string
		expectError         bool
		expectSecretInDst   bool
		expectFQDN          bool
		expectSourceDeleted bool // Expect source secret to be deleted after migration
	}{
		{
			name: "upgrade scenario - migrate secret with FQDN",
			setupSecrets: func(cs *fake.Clientset) {
				// Secret exists in controller namespace only
				_, _ = cs.CoreV1().Secrets(controllerNs).Create(context.Background(), &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: controllerNs,
					},
					Data: map[string][]byte{
						secretKey: []byte(originalConnURL),
					},
				}, metav1.CreateOptions{})
			},
			controllerNs:        controllerNs,
			infraNs:             infraNs,
			expectError:         false,
			expectSecretInDst:   true,
			expectFQDN:          true,
			expectSourceDeleted: true, // Source should be deleted after successful migration
		},
		{
			name: "already migrated - no-op",
			setupSecrets: func(cs *fake.Clientset) {
				// Secret exists in both namespaces
				_, _ = cs.CoreV1().Secrets(controllerNs).Create(context.Background(), &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: controllerNs,
					},
					Data: map[string][]byte{
						secretKey: []byte(originalConnURL),
					},
				}, metav1.CreateOptions{})
				_, _ = cs.CoreV1().Secrets(infraNs).Create(context.Background(), &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: infraNs,
					},
					Data: map[string][]byte{
						secretKey: []byte(expectedFQDN),
					},
				}, metav1.CreateOptions{})
			},
			controllerNs:        controllerNs,
			infraNs:             infraNs,
			expectError:         false,
			expectSecretInDst:   true,
			expectFQDN:          true,  // Should preserve existing FQDN
			expectSourceDeleted: false, // No migration happened, source untouched
		},
		{
			name: "fresh install - no secret anywhere",
			setupSecrets: func(cs *fake.Clientset) {
				// No secrets created
			},
			controllerNs:        controllerNs,
			infraNs:             infraNs,
			expectError:         false,
			expectSecretInDst:   false,
			expectSourceDeleted: false, // No source to delete
		},
		{
			name: "same namespace - no migration",
			setupSecrets: func(cs *fake.Clientset) {
				_, _ = cs.CoreV1().Secrets(controllerNs).Create(context.Background(), &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      secretName,
						Namespace: controllerNs,
					},
					Data: map[string][]byte{
						secretKey: []byte(originalConnURL),
					},
				}, metav1.CreateOptions{})
			},
			controllerNs:        controllerNs,
			infraNs:             controllerNs, // Same namespace
			expectError:         false,
			expectSecretInDst:   false, // No migration should happen
			expectSourceDeleted: false, // No migration happened
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset()
			tt.setupSecrets(clientset)

			err := migrateMaaSDBSecretToInfraNamespace(context.Background(), tt.controllerNs, tt.infraNs, clientset)

			if tt.expectError && err == nil {
				t.Errorf("expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.expectSecretInDst {
				secret, err := clientset.CoreV1().Secrets(tt.infraNs).Get(context.Background(), secretName, metav1.GetOptions{})
				if err != nil {
					t.Errorf("expected secret in %s but got error: %v", tt.infraNs, err)
					return
				}

				connURL := string(secret.Data[secretKey])
				if tt.expectFQDN && connURL != expectedFQDN {
					t.Errorf("expected FQDN connection URL %q, got %q", expectedFQDN, connURL)
				}

				// Verify labels and annotations (only for newly migrated secrets)
				if tt.name == "upgrade scenario - migrate secret with FQDN" {
					if secret.Labels["app.kubernetes.io/managed-by"] != "maas-controller" {
						t.Errorf("expected managed-by label, got: %v", secret.Labels)
					}
					if secret.Annotations["maas.opendatahub.io/migrated-from"] != tt.controllerNs {
						t.Errorf("expected migrated-from annotation, got: %v", secret.Annotations)
					}
				}
			} else if !tt.expectSecretInDst {
				_, err := clientset.CoreV1().Secrets(tt.infraNs).Get(context.Background(), secretName, metav1.GetOptions{})
				if err == nil && tt.infraNs != tt.controllerNs {
					t.Errorf("did not expect secret in %s but found one", tt.infraNs)
				}
			}

			// Verify source secret deletion
			if tt.expectSourceDeleted {
				_, err := clientset.CoreV1().Secrets(tt.controllerNs).Get(context.Background(), secretName, metav1.GetOptions{})
				if err == nil {
					t.Errorf("expected source secret in %s to be deleted but it still exists", tt.controllerNs)
				} else if !errors.IsNotFound(err) {
					t.Errorf("unexpected error checking source secret deletion: %v", err)
				}
			} else if !tt.expectSourceDeleted && tt.controllerNs != tt.infraNs {
				// If we don't expect deletion and namespaces differ, source should still exist (unless fresh install)
				if tt.name != "fresh install - no secret anywhere" {
					_, err := clientset.CoreV1().Secrets(tt.controllerNs).Get(context.Background(), secretName, metav1.GetOptions{})
					if errors.IsNotFound(err) {
						t.Errorf("expected source secret in %s to still exist but it was deleted", tt.controllerNs)
					}
				}
			}
		})
	}
}
