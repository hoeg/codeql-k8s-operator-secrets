// Stub of k8s.io/api/apps/v1, enough to embed ObjectMeta in a non-CR object.
package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Deployment is a stub of appsv1.Deployment.
type Deployment struct {
	metav1.TypeMeta
	metav1.ObjectMeta
}
