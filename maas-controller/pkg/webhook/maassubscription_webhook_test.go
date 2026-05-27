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

package webhook

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	maasv1alpha1 "github.com/opendatahub-io/models-as-a-service/maas-controller/api/maas/v1alpha1"
)

func TestMaaSSubscriptionValidator_ValidateCreate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = maasv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name         string
		subscription *maasv1alpha1.MaaSSubscription
		namespace    *corev1.Namespace
		wantErr      bool
		errContains  string
	}{
		{
			name: "allow subscription in default tenant namespace",
			subscription: &maasv1alpha1.MaaSSubscription{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sub",
					Namespace: DefaultTenantNamespace,
				},
			},
			namespace: nil, // Not needed for default namespace
			wantErr:   false,
		},
		{
			name: "allow subscription in labeled namespace",
			subscription: &maasv1alpha1.MaaSSubscription{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sub",
					Namespace: "ai-tenant-redteam",
				},
			},
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "ai-tenant-redteam",
					Labels: map[string]string{
						TenantNamespaceLabel: "",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "reject subscription in unlabeled namespace",
			subscription: &maasv1alpha1.MaaSSubscription{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sub",
					Namespace: "random-namespace",
				},
			},
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "random-namespace",
				},
			},
			wantErr:     true,
			errContains: "not enabled for MaaS tenant resources",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objs []runtime.Object
			if tt.namespace != nil {
				objs = append(objs, tt.namespace)
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()

			validator := &MaaSSubscriptionValidator{
				Client: client,
				Validator: &TenantNamespaceValidator{
					Client: client,
				},
			}

			_, err := validator.ValidateCreate(context.Background(), tt.subscription)

			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCreate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.errContains != "" && (err == nil || !contains(err.Error(), tt.errContains)) {
				t.Errorf("ValidateCreate() error = %v, want error containing %q", err, tt.errContains)
			}
		})
	}
}

func TestMaaSSubscriptionValidator_ValidateUpdate(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = maasv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &MaaSSubscriptionValidator{
		Client: client,
		Validator: &TenantNamespaceValidator{
			Client: client,
		},
	}

	oldSub := &maasv1alpha1.MaaSSubscription{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sub",
			Namespace: DefaultTenantNamespace,
		},
	}

	newSub := &maasv1alpha1.MaaSSubscription{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sub",
			Namespace: DefaultTenantNamespace,
		},
	}

	// Update should not validate namespace (it's immutable)
	_, err := validator.ValidateUpdate(context.Background(), oldSub, newSub)
	if err != nil {
		t.Errorf("ValidateUpdate() unexpected error: %v", err)
	}
}

func TestMaaSSubscriptionValidator_ValidateDelete(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = maasv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &MaaSSubscriptionValidator{
		Client: client,
		Validator: &TenantNamespaceValidator{
			Client: client,
		},
	}

	sub := &maasv1alpha1.MaaSSubscription{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sub",
			Namespace: DefaultTenantNamespace,
		},
	}

	// Delete should not validate
	_, err := validator.ValidateDelete(context.Background(), sub)
	if err != nil {
		t.Errorf("ValidateDelete() unexpected error: %v", err)
	}
}
