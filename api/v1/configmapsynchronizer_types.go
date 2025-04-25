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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ConfigMapSynchronizerSpec defines the desired state of ConfigMapSynchronizer.
type ConfigMapSynchronizerSpec struct {
	// Source defines the external API source configuration
	Source SourceConfig `json:"source"`

	// Target defines the target ConfigMap configuration
	Target TargetConfig `json:"target"`

	// Template defines the Go template configuration for generating the ConfigMap
	Template TemplateConfig `json:"template"`
}

// SourceConfig defines the external API source configuration
type SourceConfig struct {
	// APIEndpoint is the URL of the external API endpoint
	APIEndpoint string `json:"apiEndpoint"`

	// Method is the HTTP method to use for the API request
	Method string `json:"method"`

	// Headers contains HTTP headers to include in the API request
	// Headers can reference secrets using ${SECRET_REF:namespace:name:key} format
	Headers map[string]string `json:"headers,omitempty"`

	// PollingInterval is the interval at which to poll the API
	// Format is a duration string (e.g. "60s", "5m")
	PollingInterval string `json:"pollingInterval"`

	// ResponseFormat defines the format of the API response
	// Currently only "json" is supported
	ResponseFormat string `json:"responseFormat,omitempty"`

	// Auth defines the authentication configuration for the API
	// If not specified, no authentication will be used
	Auth *AuthConfig `json:"auth,omitempty"`
}

// TargetConfig defines the target ConfigMap configuration
type TargetConfig struct {
	// ConfigMapName is the name of the target ConfigMap
	ConfigMapName string `json:"configMapName"`

	// Namespace is the namespace of the target ConfigMap
	Namespace string `json:"namespace"`

	// UpdateStrategy defines how to update the ConfigMap
	// Valid values are "patch" or "replace"
	UpdateStrategy string `json:"updateStrategy"`

	// RestartDeployments defines which deployments should be restarted when the ConfigMap changes
	// If empty, no deployments will be restarted
	// Each string should be in the format "namespace/name"
	// If namespace is omitted, the target ConfigMap's namespace will be used
	RestartDeployments []string `json:"restartDeployments,omitempty"`
}

// TemplateConfig defines the Go template configuration for generating the ConfigMap
type TemplateConfig struct {
	// TemplateConfigMapRef is a reference to a ConfigMap containing Go templates
	// The ConfigMap should contain one or more keys with Go template content
	TemplateConfigMapRef TemplateConfigMapRef `json:"templateConfigMapRef"`

	// ValueMappings defines how to map API response fields to template variables
	// Each mapping specifies a JSONPath expression to extract data from the API response
	// and the variable name to use in the Go template
	ValueMappings []ValueMapping `json:"valueMappings"`
}

// TemplateConfigMapRef defines a reference to a ConfigMap containing Go templates
type TemplateConfigMapRef struct {
	// Name is the name of the ConfigMap containing the templates
	Name string `json:"name"`

	// Namespace is the namespace of the ConfigMap
	// If empty, the namespace of the ConfigMapSynchronizer is used
	Namespace string `json:"namespace,omitempty"`
}

// ValueMapping defines how to map an API response field to a template variable
type ValueMapping struct {
	// JSONPath is the JSONPath expression to extract data from the API response
	JSONPath string `json:"jsonPath"`

	// VariableName is the name of the variable to use in the Go template
	VariableName string `json:"variableName"`

	// DefaultValue is an optional default value to use if the JSONPath doesn't match
	DefaultValue string `json:"defaultValue,omitempty"`
}

// AuthConfig defines authentication configuration for the API
type AuthConfig struct {
	// Type is the type of authentication to use
	// Valid values are "basic" or "bearer"
	Type string `json:"type"`

	// Basic contains configuration for HTTP Basic Authentication
	// Only used when Type is "basic"
	Basic *BasicAuthConfig `json:"basic,omitempty"`

	// Bearer contains configuration for Bearer Token Authentication
	// Only used when Type is "bearer"
	Bearer *BearerAuthConfig `json:"bearer,omitempty"`
}

// BasicAuthConfig defines configuration for HTTP Basic Authentication
type BasicAuthConfig struct {
	// Username is the username for basic authentication
	Username string `json:"username"`

	// PasswordSecretRef is a reference to a secret containing the password
	PasswordSecretRef SecretRef `json:"passwordSecretRef"`
}

// SecretRef defines a reference to a Kubernetes Secret
type SecretRef struct {
	// Name is the name of the secret
	Name string `json:"name"`

	// Namespace is the namespace of the secret
	// If empty, the namespace of the ConfigMapSynchronizer is used
	Namespace string `json:"namespace,omitempty"`

	// Key is the key in the secret containing the data
	Key string `json:"key"`
}

// BearerAuthConfig defines configuration for Bearer Token Authentication
type BearerAuthConfig struct {
	// TokenSecretRef is a reference to a secret containing the bearer token
	TokenSecretRef SecretRef `json:"tokenSecretRef"`
}

// ConfigMapSynchronizerStatus defines the observed state of ConfigMapSynchronizer.
type ConfigMapSynchronizerStatus struct {
	// LastSyncTime is the timestamp of the last successful synchronization
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`

	// LastSyncState indicates the state of the last synchronization attempt
	LastSyncState string `json:"lastSyncState,omitempty"`

	// Message provides additional information about the synchronization state
	Message string `json:"message,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Target ConfigMap",type="string",JSONPath=".spec.target.configMapName"
// +kubebuilder:printcolumn:name="Namespace",type="string",JSONPath=".spec.target.namespace"
// +kubebuilder:printcolumn:name="Last Sync",type="string",JSONPath=".status.lastSyncTime"
// +kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.lastSyncState"

// ConfigMapSynchronizer is the Schema for the configmapsynchronizers API.
type ConfigMapSynchronizer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfigMapSynchronizerSpec   `json:"spec,omitempty"`
	Status ConfigMapSynchronizerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConfigMapSynchronizerList contains a list of ConfigMapSynchronizer.
type ConfigMapSynchronizerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConfigMapSynchronizer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfigMapSynchronizer{}, &ConfigMapSynchronizerList{})
}
