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
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

func TestProcessTemplates(t *testing.T) {
	// Setup a logger for testing
	log := logf.Log.WithName("template-test")
	ctx := logf.IntoContext(context.Background(), log)

	// Create a test scheme
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = apiconfigv1.AddToScheme(scheme)

	// Create a fake client
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	// Create a reconciler with the fake client
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: client,
		Scheme: scheme,
	}

	// Create a template ConfigMap
	templateConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "haproxy-template",
			Namespace: "default",
		},
		Data: map[string]string{
			"haproxy.cfg": `
global
  log /dev/log local0
  log /dev/log local1 notice
  daemon

defaults
  log global
  mode http
  timeout connect 5000
  timeout client  50000
  timeout server  50000

frontend http_front
  bind *:80
  default_backend http_back

backend http_back
  balance roundrobin
  option httpchk GET /health
  http-check expect status 200
  {{ range .Backends }}
  server {{ .Name }} {{ .Host }}:{{ if .Port }}{{ .Port }}{{ else }}80{{ end }} check {{ if .Backup }}backup{{ end }}
  {{ end }}
`,
		},
	}

	// Create a test instance
	instance := &apiconfigv1.ConfigMapSynchronizer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sync",
			Namespace: "default",
		},
		Spec: apiconfigv1.ConfigMapSynchronizerSpec{
			Source: apiconfigv1.SourceConfig{
				APIEndpoint:     "https://api.example.com/backends",
				Method:          "GET",
				PollingInterval: "1m",
				ResponseFormat:  "json",
			},
			Target: apiconfigv1.TargetConfig{
				ConfigMapName:      "haproxy-config",
				Namespace:          "default",
				UpdateStrategy:     "replace",
				RestartDeployments: []string{"haproxy"},
			},
			Template: apiconfigv1.TemplateConfig{
				TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
					Name: "haproxy-template",
				},
				ValueMappings: []apiconfigv1.ValueMapping{
					{
						JSONPath:     "$.backends",
						VariableName: "Backends",
					},
				},
			},
		},
	}

	// Create a mock API response
	apiData := map[string]interface{}{
		"backends": []interface{}{
			map[string]interface{}{
				"Name":   "web1",
				"Host":   "10.0.0.1",
				"Port":   8080,
				"Backup": false,
			},
			map[string]interface{}{
				"Name":   "web2",
				"Host":   "10.0.0.2",
				"Port":   8080,
				"Backup": false,
			},
			map[string]interface{}{
				"Name":   "web3",
				"Host":   "10.0.0.3",
				"Port":   8080,
				"Backup": true,
			},
		},
	}

	// Test the processTemplates function
	t.Run("ProcessTemplates", func(t *testing.T) {
		result, err := reconciler.processTemplates(ctx, apiData, templateConfigMap, instance)
		assert.NoError(t, err)
		assert.Contains(t, result, "haproxy.cfg")

		// Check that the template was properly rendered
		haproxyConfig := result["haproxy.cfg"]
		assert.Contains(t, haproxyConfig, "server web1 10.0.0.1:8080 check")
		assert.Contains(t, haproxyConfig, "server web2 10.0.0.2:8080 check")
		assert.Contains(t, haproxyConfig, "server web3 10.0.0.3:8080 check backup")
	})

	// Test with missing JSONPath
	t.Run("ProcessTemplatesWithMissingPath", func(t *testing.T) {
		// Create a modified template that doesn't require Backends to be an array
		modifiedTemplate := templateConfigMap.DeepCopy()
		modifiedTemplate.Data["haproxy.cfg"] = `
global
  log /dev/log local0
  log /dev/log local1 notice
  daemon

defaults
  log global
  mode http
  timeout connect 5000
  timeout client  50000
  timeout server  50000

frontend http_front
  bind *:80
  default_backend http_back

backend http_back
  balance roundrobin
  option httpchk GET /health
  http-check expect status 200
  # No backends: {{ .Backends }}
`

		// Create an instance with a JSONPath that doesn't exist in the data
		instanceWithMissingPath := instance.DeepCopy()
		instanceWithMissingPath.Spec.Template.ValueMappings[0].JSONPath = "$.nonexistent"
		instanceWithMissingPath.Spec.Template.ValueMappings[0].DefaultValue = "No backends found"

		result, err := reconciler.processTemplates(ctx, apiData, modifiedTemplate, instanceWithMissingPath)
		assert.NoError(t, err)
		assert.Contains(t, result, "haproxy.cfg")

		// The template should be rendered with the default value
		haproxyConfig := result["haproxy.cfg"]
		assert.Contains(t, haproxyConfig, "# No backends: No backends found")
	})

	// Test with invalid template
	t.Run("ProcessTemplatesWithInvalidTemplate", func(t *testing.T) {
		invalidTemplateConfigMap := templateConfigMap.DeepCopy()
		invalidTemplateConfigMap.Data["haproxy.cfg"] = `{{ .InvalidSyntax }`

		_, err := reconciler.processTemplates(ctx, apiData, invalidTemplateConfigMap, instance)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse template")
	})
}
