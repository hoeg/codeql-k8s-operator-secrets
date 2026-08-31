// Stub of k8s.io/apimachinery/pkg/apis/meta/v1.
package v1

// ObjectMeta is a stub of metav1.ObjectMeta.
type ObjectMeta struct {
	Name        string
	Namespace   string
	Labels      map[string]string
	Annotations map[string]string
}

// TypeMeta is a stub of metav1.TypeMeta.
type TypeMeta struct {
	Kind       string
	APIVersion string
}

// ListMeta is a stub of metav1.ListMeta.
//
// Present because isRegisterableApiObjectType accepts TypeMeta + ListMeta as
// well as TypeMeta + ObjectMeta: a `FooList` embeds this one, not ObjectMeta,
// and the library deliberately admits list types as custom resource types.
type ListMeta struct {
	ResourceVersion string
	Continue        string
}
