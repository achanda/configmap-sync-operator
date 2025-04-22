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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/PaesslerAG/jsonpath"
	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConfigMapSynchronizerReconciler reconciles a ConfigMapSynchronizer object
type ConfigMapSynchronizerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=apiconfig.example.com,resources=configmapsynchronizers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apiconfig.example.com,resources=configmapsynchronizers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apiconfig.example.com,resources=configmapsynchronizers/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ConfigMapSynchronizer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *ConfigMapSynchronizerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the ConfigMapSynchronizer instance
	instance := &apiconfigv1.ConfigMapSynchronizer{}
	err := r.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Return and don't requeue
			return ctrl.Result{}, nil
		}
		// Error reading the object - requeue the request.
		log.Error(err, "Failed to get ConfigMapSynchronizer")
		return ctrl.Result{}, err
	}

	// Parse the polling interval
	pollingInterval, err := time.ParseDuration(instance.Spec.Source.PollingInterval)
	if err != nil {
		log.Error(err, "Invalid polling interval format", "pollingInterval", instance.Spec.Source.PollingInterval)

		// Update status to reflect the error
		instance.Status.LastSyncState = "Error"
		instance.Status.Message = fmt.Sprintf("Invalid polling interval format: %s", err)
		err = r.Status().Update(ctx, instance)
		if err != nil {
			log.Error(err, "Failed to update ConfigMapSynchronizer status")
		}

		return ctrl.Result{}, err
	}

	// Check if we should sync based on the polling interval
	shouldSync := true
	if instance.Status.LastSyncTime != nil {
		// Parse the polling interval
		pollingInterval, err := time.ParseDuration(instance.Spec.Source.PollingInterval)
		if err != nil {
			log.Error(err, "Failed to parse polling interval, using default of 5 minutes")
			pollingInterval = 5 * time.Minute
		}

		// Check if enough time has passed since the last sync
		lastSync := instance.Status.LastSyncTime.Time
		nextSync := lastSync.Add(pollingInterval)
		if time.Now().Before(nextSync) {
			shouldSync = false
			log.Info("Skipping sync due to polling interval", "lastSync", lastSync, "nextSync", nextSync)
			return ctrl.Result{RequeueAfter: time.Until(nextSync)}, nil
		}
	}

	// If we should sync, fetch the API data
	if shouldSync {
		// Perform the synchronization
		if err := r.syncConfigMap(ctx, instance); err != nil {
			log.Error(err, "Failed to synchronize ConfigMap")

			// Update status to reflect the error
			instance.Status.LastSyncState = "Error"
			instance.Status.Message = fmt.Sprintf("Synchronization failed: %s", err)
			err = r.Status().Update(ctx, instance)
			if err != nil {
				log.Error(err, "Failed to update ConfigMapSynchronizer status")
			}

			return ctrl.Result{RequeueAfter: pollingInterval}, nil
		}

		// Update status to reflect successful synchronization
		now := metav1.Now()
		instance.Status.LastSyncTime = &now
		instance.Status.LastSyncState = "Synced"
		instance.Status.Message = "Successfully synchronized ConfigMap"
		err = r.Status().Update(ctx, instance)
		if err != nil {
			log.Error(err, "Failed to update ConfigMapSynchronizer status")
			return ctrl.Result{}, err
		}
	}

	// Requeue based on the polling interval
	return ctrl.Result{RequeueAfter: pollingInterval}, nil
}

// syncConfigMap fetches data from the external API and updates the target ConfigMap
func (r *ConfigMapSynchronizerReconciler) syncConfigMap(ctx context.Context, instance *apiconfigv1.ConfigMapSynchronizer) error {
	log := logf.FromContext(ctx)

	// Fetch data from the external API
	apiData, err := r.fetchAPIData(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to fetch API data: %w", err)
	}

	// Fetch the template ConfigMap
	templateConfigMap, err := r.fetchTemplateConfigMap(ctx, instance)
	if err != nil {
		return fmt.Errorf("failed to fetch template ConfigMap: %w", err)
	}

	// Process the API response using JSONPath expressions and apply to templates
	configData, err := r.processTemplates(ctx, apiData, templateConfigMap, instance)
	if err != nil {
		return fmt.Errorf("failed to process templates: %w", err)
	}

	// Get or create the target ConfigMap
	targetNamespace := instance.Spec.Target.Namespace
	targetName := instance.Spec.Target.ConfigMapName

	configMap := &corev1.ConfigMap{}
	err = r.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: targetName}, configMap)

	isNewConfigMap := false
	configMapChanged := false
	if err != nil {
		if errors.IsNotFound(err) {
			// ConfigMap doesn't exist, create a new one
			configMap = &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      targetName,
					Namespace: targetNamespace,
				},
				Data: configData,
			}
			isNewConfigMap = true
			configMapChanged = true
		} else {
			return fmt.Errorf("failed to get target ConfigMap: %w", err)
		}
	}

	// Set owner reference if the ConfigMap is in the same namespace as the CR
	if instance.Namespace == targetNamespace {
		if err := controllerutil.SetControllerReference(instance, configMap, r.Scheme); err != nil {
			return fmt.Errorf("failed to set owner reference: %w", err)
		}
	}

	// Update the ConfigMap based on the update strategy
	if isNewConfigMap {
		if err := r.Create(ctx, configMap); err != nil {
			return fmt.Errorf("failed to create ConfigMap: %w", err)
		}
		log.Info("Created new ConfigMap", "namespace", targetNamespace, "name", targetName)
	} else {
		// Check if the ConfigMap data will change
		configMapChanged = r.isConfigMapDataChanged(configMap, configData, instance.Spec.Target.UpdateStrategy)

		// Update existing ConfigMap based on the update strategy
		switch instance.Spec.Target.UpdateStrategy {
		case "replace":
			// Replace all data
			configMap.Data = configData
		case "patch":
			// Patch only the keys specified in the mapping
			if configMap.Data == nil {
				configMap.Data = make(map[string]string)
			}
			for k, v := range configData {
				configMap.Data[k] = v
			}
		default:
			return fmt.Errorf("invalid update strategy: %s", instance.Spec.Target.UpdateStrategy)
		}

		if err := r.Update(ctx, configMap); err != nil {
			return fmt.Errorf("failed to update ConfigMap: %w", err)
		}
		log.Info("Updated ConfigMap", "namespace", targetNamespace, "name", targetName, "strategy", instance.Spec.Target.UpdateStrategy)
	}

	// If the ConfigMap data changed and there are deployments to restart, trigger rolling restarts
	if configMapChanged && len(instance.Spec.Target.RestartDeployments) > 0 {
		log.Info("ConfigMap data changed, triggering rolling restarts for deployments")
		if err := r.restartDeployments(ctx, instance); err != nil {
			return fmt.Errorf("failed to restart deployments: %w", err)
		}
	}

	return nil
}

// fetchAPIData fetches data from the external API
func (r *ConfigMapSynchronizerReconciler) fetchAPIData(ctx context.Context, instance *apiconfigv1.ConfigMapSynchronizer) (map[string]interface{}, error) {
	log := logf.FromContext(ctx)

	// Create a new HTTP client
	client := &http.Client{}

	// Create a new HTTP request
	req, err := http.NewRequestWithContext(ctx, instance.Spec.Source.Method, instance.Spec.Source.APIEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add headers to the request
	for key, value := range instance.Spec.Source.Headers {
		// Process secret references in headers
		if strings.Contains(value, "${SECRET_REF:") {
			resolvedValue, err := r.resolveSecretRef(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve secret reference in header %s: %w", key, err)
			}
			value = resolvedValue
		}
		req.Header.Add(key, value)
	}

	// Send the request
	log.Info("Sending request to external API", "endpoint", instance.Spec.Source.APIEndpoint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Error(cerr, "Failed to close response body")
		}
	}()

	// Check the response status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("received non-success status code: %d", resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse the JSON response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return result, nil
}

// fetchTemplateConfigMap fetches the template ConfigMap referenced in the CR
func (r *ConfigMapSynchronizerReconciler) fetchTemplateConfigMap(ctx context.Context, instance *apiconfigv1.ConfigMapSynchronizer) (*corev1.ConfigMap, error) {
	// Determine the namespace to use
	namespace := instance.Spec.Template.TemplateConfigMapRef.Namespace
	if namespace == "" {
		namespace = instance.Namespace
	}

	// Get the template ConfigMap
	templateConfigMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      instance.Spec.Template.TemplateConfigMapRef.Name,
	}, templateConfigMap)

	if err != nil {
		return nil, fmt.Errorf("failed to get template ConfigMap: %w", err)
	}

	return templateConfigMap, nil
}

// processTemplates processes the API data using JSONPath expressions and applies it to Go templates
func (r *ConfigMapSynchronizerReconciler) processTemplates(ctx context.Context, apiData map[string]interface{}, templateConfigMap *corev1.ConfigMap, instance *apiconfigv1.ConfigMapSynchronizer) (map[string]string, error) {
	log := logf.FromContext(ctx)
	result := make(map[string]string)

	// Extract values from API data using JSONPath expressions
	templateValues := make(map[string]interface{})
	for _, mapping := range instance.Spec.Template.ValueMappings {
		// Extract the value using JSONPath
		value, err := jsonpath.Get(mapping.JSONPath, apiData)
		if err != nil {
			log.Info("Failed to extract value using JSONPath, using default value",
				"jsonPath", mapping.JSONPath,
				"error", err,
				"defaultValue", mapping.DefaultValue)

			// Use default value if provided
			if mapping.DefaultValue != "" {
				templateValues[mapping.VariableName] = mapping.DefaultValue
			}
			continue
		}

		// Add the value to the template values
		templateValues[mapping.VariableName] = value
	}

	// Process each template in the ConfigMap
	for templateKey, templateContent := range templateConfigMap.Data {
		// Parse the template to check for required variables
		tmpl, err := template.New(templateKey).Parse(templateContent)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", templateKey, err)
		}

		// No variable validation - let the template engine handle missing variables

		// Execute the template
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, templateValues); err != nil {
			// Try to extract variable name from error message
			varName := "unknown"
			errStr := err.Error()
			// Common error pattern: "map has no entry for key "VarName""
			if strings.Contains(errStr, "map has no entry for key") {
				parts := strings.Split(errStr, "\"")
				if len(parts) >= 3 {
					varName = parts[1]
				}
			}
			return nil, fmt.Errorf("failed to execute template %s: missing variable '%s': %w", templateKey, varName, err)
		}

		// Add the result to the output
		result[templateKey] = buf.String()
	}

	return result, nil
}

// resolveSecretRef resolves a secret reference in the format ${SECRET_REF:namespace:name:key}
func (r *ConfigMapSynchronizerReconciler) resolveSecretRef(ctx context.Context, value string) (string, error) {
	// Define a regex pattern to match secret references
	pattern := regexp.MustCompile(`\$\{SECRET_REF:([^:]+):([^:]+):([^}]+)\}`)
	matches := pattern.FindStringSubmatch(value)

	if len(matches) != 4 {
		return "", fmt.Errorf("invalid secret reference format: %s", value)
	}

	// Extract the namespace, name, and key from the matches
	namespace := matches[1]
	name := matches[2]
	key := matches[3]

	// Fetch the secret
	secret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}

	// Extract the value from the secret
	valueBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("key %s not found in secret %s/%s", key, namespace, name)
	}

	return string(valueBytes), nil
}

// isConfigMapDataChanged checks if the ConfigMap data would change based on the update strategy
func (r *ConfigMapSynchronizerReconciler) isConfigMapDataChanged(configMap *corev1.ConfigMap, newData map[string]string, updateStrategy string) bool {
	switch updateStrategy {
	case "replace":
		// For replace strategy, check if the data is different
		if len(configMap.Data) != len(newData) {
			return true
		}
		for key, value := range newData {
			currentValue, exists := configMap.Data[key]
			if !exists || currentValue != value {
				return true
			}
		}
		return false
	case "patch":
		// For patch strategy, check if any of the new keys are different
		for key, value := range newData {
			currentValue, exists := configMap.Data[key]
			if !exists || currentValue != value {
				return true
			}
		}
		return false
	default:
		// Default to replace strategy
		return true
	}
}

// calculateConfigMapSHA256 calculates a SHA256 hash of the ConfigMap data
func (r *ConfigMapSynchronizerReconciler) calculateConfigMapSHA256(configMap *corev1.ConfigMap) string {
	// Create a deterministic representation of the ConfigMap data
	keys := make([]string, 0, len(configMap.Data))
	for k := range configMap.Data {
		keys = append(keys, k)
	}

	// Sort keys for deterministic order
	sort.Strings(keys)

	// Create a string with key-value pairs
	var dataStr strings.Builder
	for _, k := range keys {
		dataStr.WriteString(k)
		dataStr.WriteString(":")
		dataStr.WriteString(configMap.Data[k])
		dataStr.WriteString(";")
	}

	// Calculate SHA256 hash
	hash := sha256.Sum256([]byte(dataStr.String()))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes for shorter hash
}

// restartDeployments performs rolling restarts of the specified deployments by updating annotations
func (r *ConfigMapSynchronizerReconciler) restartDeployments(ctx context.Context, instance *apiconfigv1.ConfigMapSynchronizer) error {
	log := logf.FromContext(ctx)

	// Get the target ConfigMap
	configMap := &corev1.ConfigMap{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: instance.Spec.Target.Namespace,
		Name:      instance.Spec.Target.ConfigMapName,
	}, configMap)
	if err != nil {
		return fmt.Errorf("failed to get ConfigMap for deployment restart: %w", err)
	}

	// Calculate the SHA256 hash of the ConfigMap data
	configMapSHA := r.calculateConfigMapSHA256(configMap)
	log.Info("Calculated ConfigMap SHA", "sha", configMapSHA)

	// Process each deployment specified in the RestartDeployments list
	for _, deploymentRef := range instance.Spec.Target.RestartDeployments {
		// Parse the deployment reference (namespace/name or just name)
		namespace, name := parseDeploymentRef(deploymentRef, instance.Spec.Target.Namespace)

		// Get the deployment
		deployment := &appsv1.Deployment{}
		err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, deployment)
		if err != nil {
			log.Error(err, "Failed to get deployment", "namespace", namespace, "name", name)
			continue
		}

		// Check if the deployment already has the current ConfigMap SHA
		currentSHA, exists := deployment.Spec.Template.Annotations["configmap-sync.example.com/configmap-sha"]
		if exists && currentSHA == configMapSHA {
			log.Info("Deployment already has current ConfigMap SHA, skipping restart",
				"deployment", fmt.Sprintf("%s/%s", namespace, name))
			continue
		}

		// Update the deployment's pod template annotations with the ConfigMap SHA
		if deployment.Spec.Template.Annotations == nil {
			deployment.Spec.Template.Annotations = make(map[string]string)
		}
		deployment.Spec.Template.Annotations["configmap-sync.example.com/configmap-sha"] = configMapSHA

		// Update the deployment
		if err := r.Update(ctx, deployment); err != nil {
			log.Error(err, "Failed to update deployment with ConfigMap SHA",
				"deployment", fmt.Sprintf("%s/%s", namespace, name))
			continue
		}

		log.Info("Updated deployment with new ConfigMap SHA, triggering rolling restart",
			"deployment", fmt.Sprintf("%s/%s", namespace, name),
			"sha", configMapSHA)
	}

	return nil
}

// parseDeploymentRef parses a deployment reference string in the format "namespace/name" or "name"
// If only name is provided, the default namespace is used
func parseDeploymentRef(deploymentRef string, defaultNamespace string) (namespace string, name string) {
	parts := strings.Split(deploymentRef, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return defaultNamespace, deploymentRef
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigMapSynchronizerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&apiconfigv1.ConfigMapSynchronizer{}).
		Owns(&corev1.ConfigMap{}).
		Named("configmapsynchronizer").
		Complete(r)
}
