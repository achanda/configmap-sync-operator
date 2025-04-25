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
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

var _ = Describe("Authentication Tests", func() {
	const (
		namespace        = "default"
		basicSecretName  = "basic-auth-secret"
		bearerSecretName = "bearer-auth-secret"
		basicPasswordKey = "password"
		bearerTokenKey   = "token"
		basicUsername    = "testuser"
		basicPassword    = "testpassword"
		bearerToken      = "testtoken12345"
		customNamespace  = "custom-namespace"
	)

	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()

		// Create the basic auth secret
		basicSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      basicSecretName,
				Namespace: namespace,
			},
			Data: map[string][]byte{
				basicPasswordKey: []byte(basicPassword),
			},
		}
		err := k8sClient.Create(ctx, basicSecret)
		Expect(err).NotTo(HaveOccurred())

		// Create the bearer token secret
		bearerSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bearerSecretName,
				Namespace: namespace,
			},
			Data: map[string][]byte{
				bearerTokenKey: []byte(bearerToken),
			},
		}
		err = k8sClient.Create(ctx, bearerSecret)
		Expect(err).NotTo(HaveOccurred())

		// Create the custom namespace secret for testing namespace resolution
		customSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      basicSecretName,
				Namespace: customNamespace,
			},
			Data: map[string][]byte{
				basicPasswordKey: []byte("custom-" + basicPassword),
			},
		}

		// Create the custom namespace if it doesn't exist
		customNs := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: customNamespace,
			},
		}
		_ = k8sClient.Create(ctx, customNs) // Ignore error if namespace already exists

		err = k8sClient.Create(ctx, customSecret)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Clean up the secrets
		basicSecret := &corev1.Secret{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: basicSecretName, Namespace: namespace}, basicSecret)
		if err == nil {
			Expect(k8sClient.Delete(ctx, basicSecret)).To(Succeed())
		}

		bearerSecret := &corev1.Secret{}
		err = k8sClient.Get(ctx, types.NamespacedName{Name: bearerSecretName, Namespace: namespace}, bearerSecret)
		if err == nil {
			Expect(k8sClient.Delete(ctx, bearerSecret)).To(Succeed())
		}

		customSecret := &corev1.Secret{}
		err = k8sClient.Get(ctx, types.NamespacedName{Name: basicSecretName, Namespace: customNamespace}, customSecret)
		if err == nil {
			Expect(k8sClient.Delete(ctx, customSecret)).To(Succeed())
		}
	})

	Context("Basic Authentication", func() {
		It("should apply basic authentication to the request", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create a basic auth config
			authConfig := &apiconfigv1.AuthConfig{
				Type: "basic",
				Basic: &apiconfigv1.BasicAuthConfig{
					Username: basicUsername,
					PasswordSecretRef: apiconfigv1.SecretRef{
						Name: basicSecretName,
						Key:  basicPasswordKey,
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).NotTo(HaveOccurred())

			// Verify the Authorization header
			username, password, ok := req.BasicAuth()
			Expect(ok).To(BeTrue())
			Expect(username).To(Equal(basicUsername))
			Expect(password).To(Equal(basicPassword))
		})

		It("should apply basic authentication with custom namespace", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create a basic auth config with custom namespace
			authConfig := &apiconfigv1.AuthConfig{
				Type: "basic",
				Basic: &apiconfigv1.BasicAuthConfig{
					Username: basicUsername,
					PasswordSecretRef: apiconfigv1.SecretRef{
						Name:      basicSecretName,
						Namespace: customNamespace,
						Key:       basicPasswordKey,
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).NotTo(HaveOccurred())

			// Verify the Authorization header
			username, password, ok := req.BasicAuth()
			Expect(ok).To(BeTrue())
			Expect(username).To(Equal(basicUsername))
			Expect(password).To(Equal("custom-" + basicPassword))
		})

		It("should return an error when basic auth config is missing", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create an invalid basic auth config (missing Basic field)
			authConfig := &apiconfigv1.AuthConfig{
				Type: "basic",
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("basic auth configuration is missing"))
		})

		It("should return an error when secret does not exist", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create a basic auth config with non-existent secret
			authConfig := &apiconfigv1.AuthConfig{
				Type: "basic",
				Basic: &apiconfigv1.BasicAuthConfig{
					Username: basicUsername,
					PasswordSecretRef: apiconfigv1.SecretRef{
						Name: "non-existent-secret",
						Key:  basicPasswordKey,
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to get secret"))
		})

		It("should return an error when secret key does not exist", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create a basic auth config with non-existent key
			authConfig := &apiconfigv1.AuthConfig{
				Type: "basic",
				Basic: &apiconfigv1.BasicAuthConfig{
					Username: basicUsername,
					PasswordSecretRef: apiconfigv1.SecretRef{
						Name: basicSecretName,
						Key:  "non-existent-key",
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key non-existent-key not found in secret"))
		})
	})

	Context("Bearer Token Authentication", func() {
		It("should apply bearer token authentication to the request", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create a bearer auth config
			authConfig := &apiconfigv1.AuthConfig{
				Type: "bearer",
				Bearer: &apiconfigv1.BearerAuthConfig{
					TokenSecretRef: apiconfigv1.SecretRef{
						Name: bearerSecretName,
						Key:  bearerTokenKey,
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).NotTo(HaveOccurred())

			// Verify the Authorization header
			authHeader := req.Header.Get("Authorization")
			Expect(authHeader).To(Equal("Bearer " + bearerToken))
		})

		It("should return an error when bearer auth config is missing", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create an invalid bearer auth config (missing Bearer field)
			authConfig := &apiconfigv1.AuthConfig{
				Type: "bearer",
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("bearer auth configuration is missing"))
		})
	})

	Context("Unsupported Authentication Type", func() {
		It("should return an error for unsupported authentication type", func() {
			// Create a test HTTP request
			req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

			// Create an auth config with unsupported type
			authConfig := &apiconfigv1.AuthConfig{
				Type: "unsupported",
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err := controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported authentication type: unsupported"))
		})
	})

	Context("Integration with HTTP Requests", func() {
		It("should send authenticated requests to the mock server", func() {
			// Setup a mock server that validates authentication
			var receivedAuthHeader string
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedAuthHeader = r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
			}))
			defer mockServer.Close()

			// Create a test HTTP request
			req, err := http.NewRequest(http.MethodGet, mockServer.URL, nil)
			Expect(err).NotTo(HaveOccurred())

			// Create a bearer auth config
			authConfig := &apiconfigv1.AuthConfig{
				Type: "bearer",
				Bearer: &apiconfigv1.BearerAuthConfig{
					TokenSecretRef: apiconfigv1.SecretRef{
						Name: bearerSecretName,
						Key:  bearerTokenKey,
					},
				},
			}

			// Initialize the controller
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			// Apply the authentication
			err = controllerReconciler.applyAuthentication(ctx, req, authConfig, namespace)
			Expect(err).NotTo(HaveOccurred())

			// Send the request
			client := &http.Client{}
			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				err := resp.Body.Close()
				Expect(err).NotTo(HaveOccurred())
			}()

			// Verify the server received the correct authentication header
			Expect(receivedAuthHeader).To(Equal("Bearer " + bearerToken))
			Expect(resp.StatusCode).To(Equal(http.StatusOK))
		})
	})
})
