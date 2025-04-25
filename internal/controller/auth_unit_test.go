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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

func TestBasicAuthentication(t *testing.T) {
	// Test constants
	const (
		namespace       = "default"
		secretName      = "basic-auth-secret"
		passwordKey     = "password"
		username        = "testuser"
		password        = "testpassword"
		customNamespace = "custom-namespace"
		customPassword  = "custom-testpassword"
	)

	// Register scheme
	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// Create test secrets
	basicSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			passwordKey: []byte(password),
		},
	}

	customSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: customNamespace,
		},
		Data: map[string][]byte{
			passwordKey: []byte(customPassword),
		},
	}

	// Create fake client with test secrets
	client := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(basicSecret, customSecret).
		Build()

	// Create controller reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: client,
		Scheme: s,
	}

	// Test cases
	t.Run("Basic Auth Success", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create a basic auth config
		authConfig := &apiconfigv1.AuthConfig{
			Type: "basic",
			Basic: &apiconfigv1.BasicAuthConfig{
				Username: username,
				PasswordSecretRef: apiconfigv1.SecretRef{
					Name: secretName,
					Key:  passwordKey,
				},
			},
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.NoError(t, err)

		// Verify the Authorization header
		user, pass, ok := req.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, username, user)
		assert.Equal(t, password, pass)
	})

	t.Run("Basic Auth Custom Namespace", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create a basic auth config with custom namespace
		authConfig := &apiconfigv1.AuthConfig{
			Type: "basic",
			Basic: &apiconfigv1.BasicAuthConfig{
				Username: username,
				PasswordSecretRef: apiconfigv1.SecretRef{
					Name:      secretName,
					Namespace: customNamespace,
					Key:       passwordKey,
				},
			},
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.NoError(t, err)

		// Verify the Authorization header
		user, pass, ok := req.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, username, user)
		assert.Equal(t, customPassword, pass)
	})

	t.Run("Basic Auth Missing Config", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create an invalid basic auth config (missing Basic field)
		authConfig := &apiconfigv1.AuthConfig{
			Type: "basic",
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "basic auth configuration is missing")
	})

	t.Run("Basic Auth Secret Not Found", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create a basic auth config with non-existent secret
		authConfig := &apiconfigv1.AuthConfig{
			Type: "basic",
			Basic: &apiconfigv1.BasicAuthConfig{
				Username: username,
				PasswordSecretRef: apiconfigv1.SecretRef{
					Name: "non-existent-secret",
					Key:  passwordKey,
				},
			},
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get secret")
	})

	t.Run("Basic Auth Key Not Found", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create a basic auth config with non-existent key
		authConfig := &apiconfigv1.AuthConfig{
			Type: "basic",
			Basic: &apiconfigv1.BasicAuthConfig{
				Username: username,
				PasswordSecretRef: apiconfigv1.SecretRef{
					Name: secretName,
					Key:  "non-existent-key",
				},
			},
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key non-existent-key not found in secret")
	})
}

func TestBearerAuthentication(t *testing.T) {
	// Test constants
	const (
		namespace  = "default"
		secretName = "bearer-auth-secret"
		tokenKey   = "token"
		token      = "testtoken12345"
	)

	// Register scheme
	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// Create test secret
	bearerSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			tokenKey: []byte(token),
		},
	}

	// Create fake client with test secret
	client := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(bearerSecret).
		Build()

	// Create controller reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: client,
		Scheme: s,
	}

	// Test cases
	t.Run("Bearer Auth Success", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create a bearer auth config
		authConfig := &apiconfigv1.AuthConfig{
			Type: "bearer",
			Bearer: &apiconfigv1.BearerAuthConfig{
				TokenSecretRef: apiconfigv1.SecretRef{
					Name: secretName,
					Key:  tokenKey,
				},
			},
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.NoError(t, err)

		// Verify the Authorization header
		authHeader := req.Header.Get("Authorization")
		assert.Equal(t, "Bearer "+token, authHeader)
	})

	t.Run("Bearer Auth Missing Config", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create an invalid bearer auth config (missing Bearer field)
		authConfig := &apiconfigv1.AuthConfig{
			Type: "bearer",
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bearer auth configuration is missing")
	})
}

func TestUnsupportedAuthentication(t *testing.T) {
	// Register scheme
	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// Create fake client
	client := fake.NewClientBuilder().
		WithScheme(s).
		Build()

	// Create controller reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: client,
		Scheme: s,
	}

	// Test unsupported auth type
	t.Run("Unsupported Auth Type", func(t *testing.T) {
		// Create a test HTTP request
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com", nil)

		// Create an auth config with unsupported type
		authConfig := &apiconfigv1.AuthConfig{
			Type: "unsupported",
		}

		// Apply the authentication
		err := reconciler.applyAuthentication(context.Background(), req, authConfig, "default")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported authentication type: unsupported")
	})
}

func TestIntegrationWithHTTPRequests(t *testing.T) {
	// Test constants
	const (
		namespace  = "default"
		secretName = "bearer-auth-secret"
		tokenKey   = "token"
		token      = "testtoken12345"
	)

	// Register scheme
	s := runtime.NewScheme()
	_ = scheme.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	// Create test secret
	bearerSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			tokenKey: []byte(token),
		},
	}

	// Create fake client with test secret
	client := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(bearerSecret).
		Build()

	// Create controller reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: client,
		Scheme: s,
	}

	t.Run("Send Authenticated Request", func(t *testing.T) {
		// Setup a mock server that validates authentication
		var receivedAuthHeader string
		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer mockServer.Close()

		// Create a test HTTP request
		req, err := http.NewRequest(http.MethodGet, mockServer.URL, nil)
		assert.NoError(t, err)

		// Create a bearer auth config
		authConfig := &apiconfigv1.AuthConfig{
			Type: "bearer",
			Bearer: &apiconfigv1.BearerAuthConfig{
				TokenSecretRef: apiconfigv1.SecretRef{
					Name: secretName,
					Key:  tokenKey,
				},
			},
		}

		// Apply the authentication
		err = reconciler.applyAuthentication(context.Background(), req, authConfig, namespace)
		assert.NoError(t, err)

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer func() {
			err := resp.Body.Close()
			assert.NoError(t, err)
		}()

		// Verify the server received the correct authentication header
		assert.Equal(t, "Bearer "+token, receivedAuthHeader)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
