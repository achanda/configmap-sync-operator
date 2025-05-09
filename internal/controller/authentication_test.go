/*
Copyright 2025.

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

package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

// setupMockAuthServer creates a test server that validates authentication
func setupMockAuthServer(expectedUsername, expectedPassword string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Parse Basic Auth header
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check credentials
		credentials := strings.SplitN(string(payload), ":", 2)
		if len(credentials) != 2 || credentials[0] != expectedUsername || credentials[1] != expectedPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// If authentication is successful, return a simple JSON response
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"message": "Authentication successful",
			"data": map[string]string{
				"value": "test-data",
			},
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
}

var _ = Describe("Authentication", func() {
	Context("When using basic authentication", func() {
		const (
			namespace       = "test-namespace"
			secretName      = "api-credentials"
			secretNamespace = "secret-namespace"
			secretKey       = "password"
			username        = "testuser"
			password        = "testpassword"
		)

		var (
			mockServer *httptest.Server
			ctx        context.Context
			fakeClient client.Client
			reconciler *ConfigMapSynchronizerReconciler
		)

		BeforeEach(func() {
			ctx = context.Background()

			// Create a scheme with our API types
			scheme := k8sClient.Scheme()

			// Create a fake client
			fakeClient = fake.NewClientBuilder().WithScheme(scheme).Build()

			// Create the reconciler with the fake client
			reconciler = &ConfigMapSynchronizerReconciler{
				Client: fakeClient,
				Scheme: scheme,
			}

			// Create a mock server that expects basic auth
			mockServer = setupMockAuthServer(username, password)

			// Create a secret with the password
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: secretNamespace,
				},
				Data: map[string][]byte{
					secretKey: []byte(password),
				},
			}
			Expect(fakeClient.Create(ctx, secret)).To(Succeed())
		})

		AfterEach(func() {
			mockServer.Close()
		})

		It("should successfully authenticate with basic auth using a secret reference", func() {
			// Create a ConfigMapSynchronizer with basic auth
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth",
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "5m",
						Auth: &apiconfigv1.AuthConfig{
							Type: apiconfigv1.AuthTypeBasic,
							BasicAuth: &apiconfigv1.BasicAuthConfig{
								Username: username,
								PasswordSecretRef: &apiconfigv1.SecretKeySelector{
									Name:      secretName,
									Namespace: secretNamespace,
									Key:       secretKey,
								},
							},
						},
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:  "target-config",
						Namespace:      namespace,
						UpdateStrategy: "replace",
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "template-config",
						},
						ValueMappings: []apiconfigv1.ValueMapping{
							{
								JSONPath:     "$.data.value",
								VariableName: "Value",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, instance)).To(Succeed())

			// Create a template ConfigMap
			templateConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "template-config",
					Namespace: namespace,
				},
				Data: map[string]string{
					"config.txt": "Value: {{ .Value }}",
				},
			}
			Expect(fakeClient.Create(ctx, templateConfigMap)).To(Succeed())

			// Reconcile the instance
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-auth",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify the target ConfigMap was created with the expected data
			targetConfigMap := &corev1.ConfigMap{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      "target-config",
				Namespace: namespace,
			}, targetConfigMap)
			Expect(err).NotTo(HaveOccurred())
			Expect(targetConfigMap.Data["config.txt"]).To(Equal("Value: test-data"))
		})

		It("should fail when basic auth is configured but the secret doesn't exist", func() {
			// Create a ConfigMapSynchronizer with basic auth pointing to a non-existent secret
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth-missing-secret",
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "5m",
						Auth: &apiconfigv1.AuthConfig{
							Type: apiconfigv1.AuthTypeBasic,
							BasicAuth: &apiconfigv1.BasicAuthConfig{
								Username: username,
								PasswordSecretRef: &apiconfigv1.SecretKeySelector{
									Name:      "nonexistent-secret",
									Namespace: secretNamespace,
									Key:       secretKey,
								},
							},
						},
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:  "target-config-missing-secret",
						Namespace:      namespace,
						UpdateStrategy: "replace",
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "template-config",
						},
						ValueMappings: []apiconfigv1.ValueMapping{
							{
								JSONPath:     "$.data.value",
								VariableName: "Value",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, instance)).To(Succeed())

			// Reconcile the instance
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-auth-missing-secret",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get secret"))
		})

		It("should fail when basic auth is configured but the secret key doesn't exist", func() {
			// Create a secret with a different key
			wrongKeySecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wrong-key-secret",
					Namespace: secretNamespace,
				},
				Data: map[string][]byte{
					"wrong-key": []byte(password),
				},
			}
			Expect(fakeClient.Create(ctx, wrongKeySecret)).To(Succeed())

			// Create a ConfigMapSynchronizer with basic auth pointing to a secret with wrong key
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth-wrong-key",
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "5m",
						Auth: &apiconfigv1.AuthConfig{
							Type: apiconfigv1.AuthTypeBasic,
							BasicAuth: &apiconfigv1.BasicAuthConfig{
								Username: username,
								PasswordSecretRef: &apiconfigv1.SecretKeySelector{
									Name:      "wrong-key-secret",
									Namespace: secretNamespace,
									Key:       "nonexistent-key",
								},
							},
						},
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:  "target-config-wrong-key",
						Namespace:      namespace,
						UpdateStrategy: "replace",
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "template-config",
						},
						ValueMappings: []apiconfigv1.ValueMapping{
							{
								JSONPath:     "$.data.value",
								VariableName: "Value",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, instance)).To(Succeed())

			// Reconcile the instance
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-auth-wrong-key",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key nonexistent-key not found in secret"))
		})

		It("should fail authentication when using incorrect credentials", func() {
			// Create a secret with wrong password
			wrongPasswordSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "wrong-password-secret",
					Namespace: secretNamespace,
				},
				Data: map[string][]byte{
					secretKey: []byte("wrong-password"),
				},
			}
			Expect(fakeClient.Create(ctx, wrongPasswordSecret)).To(Succeed())

			// Create a ConfigMapSynchronizer with basic auth pointing to a secret with wrong password
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth-wrong-password",
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "5m",
						Auth: &apiconfigv1.AuthConfig{
							Type: apiconfigv1.AuthTypeBasic,
							BasicAuth: &apiconfigv1.BasicAuthConfig{
								Username: username,
								PasswordSecretRef: &apiconfigv1.SecretKeySelector{
									Name:      "wrong-password-secret",
									Namespace: secretNamespace,
									Key:       secretKey,
								},
							},
						},
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:  "target-config-wrong-password",
						Namespace:      namespace,
						UpdateStrategy: "replace",
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "template-config",
						},
						ValueMappings: []apiconfigv1.ValueMapping{
							{
								JSONPath:     "$.data.value",
								VariableName: "Value",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, instance)).To(Succeed())

			// Reconcile the instance
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-auth-wrong-password",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("received non-success status code: 401"))
		})

		It("should use the instance namespace when secret namespace is not specified", func() {
			// Create a secret in the instance namespace
			instanceNsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "instance-ns-secret",
					Namespace: namespace,
				},
				Data: map[string][]byte{
					secretKey: []byte(password),
				},
			}
			Expect(fakeClient.Create(ctx, instanceNsSecret)).To(Succeed())

			// Create a ConfigMapSynchronizer with basic auth without specifying secret namespace
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-auth-default-ns",
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "5m",
						Auth: &apiconfigv1.AuthConfig{
							Type: apiconfigv1.AuthTypeBasic,
							BasicAuth: &apiconfigv1.BasicAuthConfig{
								Username: username,
								PasswordSecretRef: &apiconfigv1.SecretKeySelector{
									Name: "instance-ns-secret",
									Key:  secretKey,
									// Namespace is intentionally omitted
								},
							},
						},
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:  "target-config-default-ns",
						Namespace:      namespace,
						UpdateStrategy: "replace",
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "template-config",
						},
						ValueMappings: []apiconfigv1.ValueMapping{
							{
								JSONPath:     "$.data.value",
								VariableName: "Value",
							},
						},
					},
				},
			}
			Expect(fakeClient.Create(ctx, instance)).To(Succeed())

			// Reconcile the instance
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "test-auth-default-ns",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify the target ConfigMap was created with the expected data
			targetConfigMap := &corev1.ConfigMap{}
			err = fakeClient.Get(ctx, types.NamespacedName{
				Name:      "target-config-default-ns",
				Namespace: namespace,
			}, targetConfigMap)
			Expect(err).NotTo(HaveOccurred())
			Expect(targetConfigMap.Data["config.txt"]).To(Equal("Value: test-data"))
		})
	})
})
