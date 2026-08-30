// Stub of k8s.io/api/core/v1, cut down to the shapes the queries match.
package v1

// Secret is a stub of corev1.Secret.
type Secret struct {
	Data       map[string][]byte
	StringData map[string]string
}

// SecretKeySelector is a stub of corev1.SecretKeySelector.
type SecretKeySelector struct {
	Key string
}
