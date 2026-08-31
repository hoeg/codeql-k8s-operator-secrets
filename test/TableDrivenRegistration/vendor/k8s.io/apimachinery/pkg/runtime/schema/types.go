// Stub of k8s.io/apimachinery/pkg/runtime/schema.
package schema

// GroupVersion is a stub of schema.GroupVersion. It is the first argument of
// AddKnownTypes, and it is a sink of SchemeRegistrationConfig like every other
// argument of that call -- nothing an API-object literal can ever flow to.
type GroupVersion struct {
	Group   string
	Version string
}
