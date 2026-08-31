// Stub of k8s.io/apimachinery/pkg/runtime, cut down to scheme registration.
package runtime

import "k8s.io/apimachinery/pkg/runtime/schema"

// Object is a stub of runtime.Object.
//
// The real interface is `GetObjectKind() schema.ObjectKind; DeepCopyObject()
// Object`, and every registered type satisfies it through generated deepcopy
// code. It is reduced to the empty interface here on purpose: the pack never
// looks at Object's method set, and the only property of it that this fixture
// depends on is the one an empty interface still has -- that assigning `&MyCR{}`
// to something of this type erases the concrete type, so that by the time the
// value reaches AddKnownTypes its static type is no longer *MyCR. Spelling out
// the real method set would force a DeepCopyObject method onto all nine fixture
// types and would change nothing that is under test.
type Object interface{}

// Scheme is a stub of runtime.Scheme.
type Scheme struct{}

// AddKnownTypes is a stub of runtime.Scheme.AddKnownTypes: the sink of
// SchemeRegistrationConfig, and one of the two methods APISchemaBuilder matches.
func (s *Scheme) AddKnownTypes(gv schema.GroupVersion, types ...Object) {}

// AddKnownTypeWithName is a stub of runtime.Scheme.AddKnownTypeWithName, the
// other method APISchemaBuilder matches.
func (s *Scheme) AddKnownTypeWithName(gv schema.GroupVersion, name string, obj Object) {}
