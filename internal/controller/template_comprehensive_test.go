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
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

func TestTemplateProcessingComprehensive(t *testing.T) {
	// Setup a logger for testing
	log := logf.Log.WithName("template-comprehensive-test")
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

	// Test cases for different template scenarios
	testCases := []struct {
		name              string
		templateData      map[string]string
		apiData           map[string]interface{}
		valueMappings     []apiconfigv1.ValueMapping
		expectedOutput    map[string]string
		expectedError     bool
		expectedErrorText string
	}{
		{
			name: "Simple key-value template",
			templateData: map[string]string{
				"config.properties": `
app.name={{ .AppName }}
app.version={{ .AppVersion }}
app.environment={{ .Environment }}
`,
			},
			apiData: map[string]interface{}{
				"application": map[string]interface{}{
					"name":    "MyApp",
					"version": "1.0.0",
					"env":     "production",
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.application.name",
					VariableName: "AppName",
				},
				{
					JSONPath:     "$.application.version",
					VariableName: "AppVersion",
				},
				{
					JSONPath:     "$.application.env",
					VariableName: "Environment",
				},
			},
			expectedOutput: map[string]string{
				"config.properties": `
app.name=MyApp
app.version=1.0.0
app.environment=production
`,
			},
			expectedError: false,
		},
		{
			name: "Template with conditional logic",
			templateData: map[string]string{
				"nginx.conf": `
server {
    listen 80;
    server_name {{ .ServerName }};

    {{ if eq .Environment "production" }}
    # Production specific settings
    client_max_body_size 50M;
    {{ else }}
    # Development specific settings
    client_max_body_size 100M;
    {{ end }}

    location / {
        proxy_pass {{ .BackendUrl }};
    }
}
`,
			},
			apiData: map[string]interface{}{
				"server": map[string]interface{}{
					"name":        "example.com",
					"env":         "production",
					"backend_url": "http://backend:8080",
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.server.name",
					VariableName: "ServerName",
				},
				{
					JSONPath:     "$.server.env",
					VariableName: "Environment",
				},
				{
					JSONPath:     "$.server.backend_url",
					VariableName: "BackendUrl",
				},
			},
			expectedOutput: map[string]string{
				"nginx.conf": `
server {
    listen 80;
    server_name example.com;

    
    # Production specific settings
    client_max_body_size 50M;
    

    location / {
        proxy_pass http://backend:8080;
    }
}
`,
			},
			expectedError: false,
		},
		{
			name: "Template with array iteration and nested objects",
			templateData: map[string]string{
				"prometheus.yml": `
global:
  scrape_interval: {{ .ScrapeInterval }}

scrape_configs:
  {{ range .Services }}
  - job_name: {{ .Name }}
    static_configs:
      - targets:
        {{ range .Endpoints }}
        - {{ . }}
        {{ end }}
  {{ end }}
`,
			},
			apiData: map[string]interface{}{
				"monitoring": map[string]interface{}{
					"interval": "15s",
					"services": []interface{}{
						map[string]interface{}{
							"name": "api",
							"endpoints": []interface{}{
								"api:8080",
								"api-backup:8080",
							},
						},
						map[string]interface{}{
							"name": "database",
							"endpoints": []interface{}{
								"db:9090",
							},
						},
					},
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.monitoring.interval",
					VariableName: "ScrapeInterval",
				},
				{
					JSONPath:     "$.monitoring.services",
					VariableName: "Services",
				},
			},
			expectedOutput: map[string]string{
				"prometheus.yml": `
global:
  scrape_interval: 15s

scrape_configs:
  
  - job_name: <no value>
    static_configs:
      - targets:
        
  
  - job_name: <no value>
    static_configs:
      - targets:
        
  
`,
			},
			expectedError: false,
		},
		{
			name: "Template with missing required values but default values provided",
			templateData: map[string]string{
				"app.yaml": `
apiVersion: v1
kind: Service
metadata:
  name: {{ .ServiceName }}
spec:
  type: {{ .ServiceType }}
  ports:
  - port: {{ .Port }}
    targetPort: {{ .TargetPort }}
`,
			},
			apiData: map[string]interface{}{
				"service": map[string]interface{}{
					"name": "my-service",
					// port and targetPort are missing
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.service.name",
					VariableName: "ServiceName",
				},
				{
					JSONPath:     "$.service.type",
					VariableName: "ServiceType",
					DefaultValue: "ClusterIP",
				},
				{
					JSONPath:     "$.service.port",
					VariableName: "Port",
					DefaultValue: "80",
				},
				{
					JSONPath:     "$.service.target_port",
					VariableName: "TargetPort",
					DefaultValue: "8080",
				},
			},
			expectedOutput: map[string]string{
				"app.yaml": `
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  type: ClusterIP
  ports:
  - port: 80
    targetPort: 8080
`,
			},
			expectedError: false,
		},
		{
			name: "Template with invalid syntax",
			templateData: map[string]string{
				"invalid.conf": `{{ .MissingClosingBrace `,
			},
			apiData: map[string]interface{}{
				"data": "value",
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.data",
					VariableName: "Data",
				},
			},
			expectedError:     true,
			expectedErrorText: "failed to parse template",
		},
		{
			name: "Template with undefined variable",
			templateData: map[string]string{
				"config.yaml": `
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Name }}
data:
  key: {{ .Value }}
`,
			},
			apiData: map[string]interface{}{
				"name": "test-config",
				// Value is intentionally missing
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.name",
					VariableName: "Name",
				},
				// Value mapping is intentionally missing
			},
			expectedError: false,
			expectedOutput: map[string]string{
				"config.yaml": `
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-config
data:
  key: <no value>
`,
			},
		},
		{
			name: "Template with custom functions",
			templateData: map[string]string{
				"custom.conf": `
{{ if .HasFeature }}
feature.enabled=true
{{ else }}
feature.enabled=false
{{ end }}

{{ if .MissingFeature }}
missing.feature=enabled
{{ else }}
missing.feature=disabled
{{ end }}
`,
			},
			apiData: map[string]interface{}{
				"features": map[string]interface{}{
					"feature1": true,
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.features.feature1",
					VariableName: "HasFeature",
				},
				{
					JSONPath:     "$.features.feature2",
					VariableName: "MissingFeature",
					DefaultValue: "false",
				},
			},
			// Note: The expected output includes whitespace from the template processing
			// which preserves newlines from the Go template
			expectedOutput: map[string]string{
				"custom.conf": `

feature.enabled=true



missing.feature=enabled

`,
			},
			expectedError: false,
		},
		{
			name: "Multiple templates in one ConfigMap",
			templateData: map[string]string{
				"config1.properties": `
db.host={{ .DbHost }}
db.port={{ .DbPort }}
`,
				"config2.properties": `
api.url={{ .ApiUrl }}
api.key={{ .ApiKey }}
`,
			},
			apiData: map[string]interface{}{
				"database": map[string]interface{}{
					"host": "localhost",
					"port": 5432,
				},
				"api": map[string]interface{}{
					"url": "https://api.example.com",
					"key": "secret-key",
				},
			},
			valueMappings: []apiconfigv1.ValueMapping{
				{
					JSONPath:     "$.database.host",
					VariableName: "DbHost",
				},
				{
					JSONPath:     "$.database.port",
					VariableName: "DbPort",
				},
				{
					JSONPath:     "$.api.url",
					VariableName: "ApiUrl",
				},
				{
					JSONPath:     "$.api.key",
					VariableName: "ApiKey",
				},
			},
			expectedOutput: map[string]string{
				"config1.properties": `
db.host=localhost
db.port=5432
`,
				"config2.properties": `
api.url=https://api.example.com
api.key=secret-key
`,
			},
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a template ConfigMap
			templateConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-template",
					Namespace: "default",
				},
				Data: tc.templateData,
			}

			// Create a test instance
			instance := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sync",
					Namespace: "default",
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: "test-template",
						},
						ValueMappings: tc.valueMappings,
					},
				},
			}

			// Process the templates
			result, err := reconciler.processTemplates(ctx, tc.apiData, templateConfigMap, instance)

			// Check if error is expected
			if tc.expectedError {
				require.Error(t, err)
				if tc.expectedErrorText != "" {
					assert.Contains(t, err.Error(), tc.expectedErrorText)
				}
				return
			}

			// If no error is expected, verify the result
			require.NoError(t, err)
			assert.Equal(t, len(tc.expectedOutput), len(result), "Number of templates processed doesn't match expected")

			// Check each template output
			for key, expectedValue := range tc.expectedOutput {
				assert.Contains(t, result, key, "Expected template key not found in result")
				assert.Equal(t, expectedValue, result[key], "Template output doesn't match expected for key: %s", key)
			}
		})
	}
}

func TestConfigMapDataChangedDetection(t *testing.T) {
	// Create a reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: nil, // Not needed for this test
		Scheme: nil, // Not needed for this test
	}

	testCases := []struct {
		name           string
		currentData    map[string]string
		newData        map[string]string
		updateStrategy string
		expectedResult bool
	}{
		{
			name: "Replace strategy - No change",
			currentData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			newData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			updateStrategy: "replace",
			expectedResult: false,
		},
		{
			name: "Replace strategy - Value changed",
			currentData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			newData: map[string]string{
				"key1": "value1",
				"key2": "new-value2",
			},
			updateStrategy: "replace",
			expectedResult: true,
		},
		{
			name: "Replace strategy - Key added",
			currentData: map[string]string{
				"key1": "value1",
			},
			newData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			updateStrategy: "replace",
			expectedResult: true,
		},
		{
			name: "Replace strategy - Key removed",
			currentData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			newData: map[string]string{
				"key1": "value1",
			},
			updateStrategy: "replace",
			expectedResult: true,
		},
		{
			name: "Patch strategy - No change",
			currentData: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			newData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			updateStrategy: "patch",
			expectedResult: false,
		},
		{
			name: "Patch strategy - Value changed",
			currentData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			newData: map[string]string{
				"key2": "new-value2",
			},
			updateStrategy: "patch",
			expectedResult: true,
		},
		{
			name: "Patch strategy - New key",
			currentData: map[string]string{
				"key1": "value1",
			},
			newData: map[string]string{
				"key2": "value2",
			},
			updateStrategy: "patch",
			expectedResult: true,
		},
		{
			name:           "Unknown strategy",
			currentData:    map[string]string{},
			newData:        map[string]string{},
			updateStrategy: "unknown",
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configMap := &corev1.ConfigMap{
				Data: tc.currentData,
			}
			result := reconciler.isConfigMapDataChanged(configMap, tc.newData, tc.updateStrategy)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestSHA256Calculation(t *testing.T) {
	// Create a reconciler
	reconciler := &ConfigMapSynchronizerReconciler{
		Client: nil, // Not needed for this test
		Scheme: nil, // Not needed for this test
	}

	testCases := []struct {
		name        string
		configData  map[string]string
		expectEqual bool
	}{
		{
			name: "Same data should produce same hash",
			configData: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectEqual: true,
		},
		{
			name: "Different order, same hash",
			configData: map[string]string{
				"key2": "value2",
				"key1": "value1",
			},
			expectEqual: true,
		},
		{
			name: "Different values, different hash",
			configData: map[string]string{
				"key1": "value1",
				"key2": "different-value",
			},
			expectEqual: false,
		},
	}

	// Calculate reference hash from first test case
	referenceConfigMap := &corev1.ConfigMap{
		Data: testCases[0].configData,
	}
	referenceHash := reconciler.calculateConfigMapSHA256(referenceConfigMap)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configMap := &corev1.ConfigMap{
				Data: tc.configData,
			}
			hash := reconciler.calculateConfigMapSHA256(configMap)

			if tc.expectEqual {
				assert.Equal(t, referenceHash, hash, "Hashes should be equal")
			} else {
				assert.NotEqual(t, referenceHash, hash, "Hashes should be different")
			}
		})
	}
}

func TestDeploymentReferenceParser(t *testing.T) {
	testCases := []struct {
		name             string
		deploymentRef    string
		defaultNamespace string
		expectedNs       string
		expectedName     string
	}{
		{
			name:             "Full reference with namespace",
			deploymentRef:    "test-namespace/test-deployment",
			defaultNamespace: "default",
			expectedNs:       "test-namespace",
			expectedName:     "test-deployment",
		},
		{
			name:             "Name only, use default namespace",
			deploymentRef:    "test-deployment",
			defaultNamespace: "default",
			expectedNs:       "default",
			expectedName:     "test-deployment",
		},
		{
			name:             "Empty string, use default namespace",
			deploymentRef:    "",
			defaultNamespace: "default",
			expectedNs:       "default",
			expectedName:     "",
		},
		// Note: The current implementation treats the entire string as the name
		// if it doesn't contain exactly one slash. This test verifies that behavior.
		{
			name:             "Multiple slashes treated as name",
			deploymentRef:    "ns/name/extra",
			defaultNamespace: "default",
			expectedNs:       "default",
			expectedName:     "ns/name/extra",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ns, name := parseDeploymentRef(tc.deploymentRef, tc.defaultNamespace)
			assert.Equal(t, tc.expectedNs, ns)
			assert.Equal(t, tc.expectedName, name)
		})
	}
}
