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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiconfigv1 "github.com/achanda/configmap-sync-operator/api/v1"
)

// Setup a mock HTTP server for API responses
func setupMockAPIServer(backendData map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(backendData)
	}))
}

var _ = Describe("ConfigMapSynchronizer Controller", func() {
	Context("When using HAProxy template with backend servers", func() {
		const (
			resourceName       = "haproxy-sync"
			templateConfigName = "haproxy-template"
			targetConfigName   = "haproxy-config"
			deploymentName     = "haproxy"
			namespace          = "default"
		)

		ctx := context.Background()
		var mockServer *httptest.Server
		var initialBackendData map[string]interface{}
		var updatedBackendData map[string]interface{}

		BeforeEach(func() {
			// Setup initial backend data
			initialBackendData = map[string]interface{}{
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
				},
			}

			// Setup updated backend data with an additional server
			updatedBackendData = map[string]interface{}{
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

			// Start the mock API server with initial data
			mockServer = setupMockAPIServer(initialBackendData)

			// Create the template ConfigMap
			templateConfigMap := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      templateConfigName,
					Namespace: namespace,
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
  server {{ .Name }} {{ .Host }}:{{ .Port }} check {{ if .Backup }}backup{{ end }}
  {{ end }}
`,
				},
			}
			err := k8sClient.Create(ctx, templateConfigMap)
			Expect(err).NotTo(HaveOccurred())

			// Create a deployment for HAProxy
			deployment := &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      deploymentName,
					Namespace: namespace,
				},
				Spec: appsv1.DeploymentSpec{
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"app": "haproxy",
						},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								"app": "haproxy",
							},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "haproxy",
									Image: "haproxy:2.4",
									Ports: []corev1.ContainerPort{
										{ContainerPort: 80},
									},
								},
							},
						},
					},
				},
			}
			err = k8sClient.Create(ctx, deployment)
			Expect(err).NotTo(HaveOccurred())

			// Create the ConfigMapSynchronizer resource
			configMapSynchronizer := &apiconfigv1.ConfigMapSynchronizer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      resourceName,
					Namespace: namespace,
				},
				Spec: apiconfigv1.ConfigMapSynchronizerSpec{
					Source: apiconfigv1.SourceConfig{
						APIEndpoint:     mockServer.URL,
						Method:          "GET",
						PollingInterval: "1m",
						ResponseFormat:  "json",
					},
					Target: apiconfigv1.TargetConfig{
						ConfigMapName:      targetConfigName,
						Namespace:          namespace,
						UpdateStrategy:     "replace",
						RestartDeployments: []string{deploymentName},
					},
					Template: apiconfigv1.TemplateConfig{
						TemplateConfigMapRef: apiconfigv1.TemplateConfigMapRef{
							Name: templateConfigName,
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
			err = k8sClient.Create(ctx, configMapSynchronizer)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			// Cleanup resources
			By("Cleaning up resources")

			// Delete the ConfigMapSynchronizer
			configMapSynchronizer := &apiconfigv1.ConfigMapSynchronizer{}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, configMapSynchronizer)
			if err == nil {
				Expect(k8sClient.Delete(ctx, configMapSynchronizer)).To(Succeed())
			}

			// Delete the template ConfigMap
			templateConfigMap := &corev1.ConfigMap{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: templateConfigName, Namespace: namespace}, templateConfigMap)
			if err == nil {
				Expect(k8sClient.Delete(ctx, templateConfigMap)).To(Succeed())
			}

			// Delete the target ConfigMap
			targetConfigMap := &corev1.ConfigMap{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: targetConfigName, Namespace: namespace}, targetConfigMap)
			if err == nil {
				Expect(k8sClient.Delete(ctx, targetConfigMap)).To(Succeed())
			}

			// Delete the deployment
			deployment := &appsv1.Deployment{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deployment)
			if err == nil {
				Expect(k8sClient.Delete(ctx, deployment)).To(Succeed())
			}

			// Close the mock server
			mockServer.Close()
		})

		It("should create a ConfigMap with rendered HAProxy configuration", func() {
			By("Reconciling the ConfigMapSynchronizer resource")
			controllerReconciler := &ConfigMapSynchronizerReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			// Check that the target ConfigMap was created
			targetConfigMap := &corev1.ConfigMap{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{Name: targetConfigName, Namespace: namespace}, targetConfigMap)
			}).Should(Succeed())

			// Verify the HAProxy configuration contains the expected backend servers
			haproxyConfig := targetConfigMap.Data["haproxy.cfg"]
			Expect(haproxyConfig).To(ContainSubstring("server web1 10.0.0.1:8080 check"))
			Expect(haproxyConfig).To(ContainSubstring("server web2 10.0.0.2:8080 check"))

			// Check the deployment has the SHA annotation
			deployment := &appsv1.Deployment{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deployment)
				if err != nil {
					return false
				}
				_, exists := deployment.Spec.Template.Annotations["configmap-sync.example.com/configmap-sha"]
				return exists
			}).Should(BeTrue())

			// Save the initial SHA
			initialSHA := deployment.Spec.Template.Annotations["configmap-sync.example.com/configmap-sha"]

			// Update the mock server to return updated backend data
			mockServer.Close()
			mockServer = setupMockAPIServer(updatedBackendData)

			// Update the API endpoint in the ConfigMapSynchronizer
			configMapSynchronizer := &apiconfigv1.ConfigMapSynchronizer{}
			err = k8sClient.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, configMapSynchronizer)
			Expect(err).NotTo(HaveOccurred())
			configMapSynchronizer.Spec.Source.APIEndpoint = mockServer.URL
			err = k8sClient.Update(ctx, configMapSynchronizer)
			Expect(err).NotTo(HaveOccurred())

			// Reconcile again to pick up the new API data
			_, err = controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName, Namespace: namespace},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify the ConfigMap was updated with the new backend server
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: targetConfigName, Namespace: namespace}, targetConfigMap)
				if err != nil {
					return false
				}
				haproxyConfig = targetConfigMap.Data["haproxy.cfg"]
				return strings.Contains(haproxyConfig, "server web3 10.0.0.3:8080 check backup")
			}).Should(BeTrue())

			// Verify the deployment was updated with a new SHA
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{Name: deploymentName, Namespace: namespace}, deployment)
				if err != nil {
					return false
				}
				newSHA := deployment.Spec.Template.Annotations["configmap-sync.example.com/configmap-sha"]
				return newSHA != "" && newSHA != initialSHA
			}).Should(BeTrue())
		})
	})
})
