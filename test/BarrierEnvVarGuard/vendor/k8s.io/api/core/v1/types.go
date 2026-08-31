// Stub of k8s.io/api/core/v1, cut down to the shapes the queries match.
package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Well-known Secret keys. TLSCertKey and ServiceAccountRootCAKey name public
// certificate material; TLSPrivateKeyKey names the private key.
const (
	TLSCertKey              = "tls.crt"
	TLSPrivateKeyKey        = "tls.key"
	ServiceAccountRootCAKey = "ca.crt"
)

// Secret is a stub of corev1.Secret.
type Secret struct {
	Data       map[string][]byte
	StringData map[string]string
}

// SecretKeySelector is a stub of corev1.SecretKeySelector.
type SecretKeySelector struct {
	Key string
}

// ConfigMap is a stub of corev1.ConfigMap: the explicitly non-secret half of
// the API, readable by every subject holding `get configmap`.
type ConfigMap struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Immutable  *bool
	Data       map[string]string
	BinaryData map[string][]byte
}

// EnvVarSource is a stub of corev1.EnvVarSource, present so that EnvVar keeps
// its real three-field shape (Value and ValueFrom are the two alternatives).
type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector
}

// EnvVar is a stub of corev1.EnvVar. Value is a literal environment-variable
// value; ValueFrom is the indirection that does not materialise the secret.
type EnvVar struct {
	Name      string
	Value     string
	ValueFrom *EnvVarSource
}

// Container is a stub of corev1.Container.
type Container struct {
	Name string
	Env  []EnvVar
}

// PodSpec is a stub of corev1.PodSpec.
type PodSpec struct {
	Containers []Container
}
