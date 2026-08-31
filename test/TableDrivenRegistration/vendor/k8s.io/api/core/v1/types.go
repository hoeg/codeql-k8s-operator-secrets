// Stub of k8s.io/api/core/v1, cut down to the shapes the queries match.
package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Secret is a stub of corev1.Secret.
//
// Unlike the Secret stub in the other test directories, this one embeds
// TypeMeta and ObjectMeta, exactly as the real corev1.Secret does. That is
// load-bearing for the negative case addUpstreamType: it makes Secret satisfy
// the *structural* half of isRegisterableApiObjectType in full, so the only
// thing that keeps it out of CustomResourceType is the k8s.io/ package
// exclusion. Without the embeds the negative would pass for the wrong reason
// and deleting the exclusion would not be detected.
type Secret struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Data       map[string][]byte
	StringData map[string]string
	Type       SecretType
}

// SecretType is a stub of corev1.SecretType, a named string type. It is here
// because it is the only plain string-ish field the real corev1.Secret has that
// is not Data or StringData, and copySecret needs one: Data and StringData are
// excluded from isCustomResourceStringishContainer by name
// (`not f instanceof K8sSecretDataField`), so a write into either could not
// become a sink even if Secret were wrongly admitted as a custom resource.
type SecretType string
