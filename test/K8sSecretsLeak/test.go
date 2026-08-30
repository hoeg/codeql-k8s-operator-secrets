package operator

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// HeadersSource mirrors humio-operator's HeadersSource: a struct that is
// reachable from the CR only through a *slice* field. Before the unwrap() fix
// the field-following recursion stopped dead at `[]HeadersSource`.
type HeadersSource struct {
	Name  string
	Value string
}

// PoolSlot is reachable from the CR only through a *fixed-size array* member,
// `[2]PoolSlot`. Its field names are deliberately unlike every other struct in
// this file, so it shares no structural Field entity with them and reaching
// PoolSlot.SlotValue therefore requires unwrap()'s ArrayType branch
// specifically -- the SliceType branch cannot stand in for it.
type PoolSlot struct {
	SlotName  string
	SlotValue string
}

// PoolEntry is reachable from the CR only through a *map value*,
// `map[string][]PoolEntry`. Reaching PoolEntry.EntryValue needs unwrap()'s
// MapType branch (the value type, never the key type) and then the SliceType
// branch, which is what makes it a test of the `*` in `unwrap*` as well. Field
// names are again distinct from every other struct here.
type PoolEntry struct {
	EntryName  string
	EntryValue string
}

// TokenString is a named string type, the shape Kubernetes CRDs use heavily
// (humio-operator's `type HumioClusterState string`). It is a DefinedType, not
// a BasicType, so `f.getType() instanceof StringType` misses it entirely.
type TokenString string

// MyCRSpec is the spec of the custom resource under test.
type MyCRSpec struct {
	Token string
	Ref   corev1.SecretKeySelector
	// SecretHeaders is the container-nested case: `[]T` does not override
	// Type.getField, so reaching HeadersSource.Value requires unwrap().
	SecretHeaders []HeadersSource
	// Slots is the fixed-size-array case: `[N]T` is an ArrayType, a distinct
	// unwrap() branch from SliceType.
	Slots [2]PoolSlot
	// PoolsByName is the map case, in the shape operators actually use
	// (humio-operator's node-pool maps). unwrap() must descend through the map
	// *value* type and then through the slice.
	PoolsByName map[string][]PoolEntry
	// NamedToken is the named-string-type case.
	NamedToken TokenString
	// RawToken is the byte-slice case.
	RawToken []byte
}

// NotACR is *structurally identical* to MyCRSpec -- same field names, same
// field types, same order, no tags -- so the Go extractor gives it the same
// underlying struct type and therefore the very same Field entities:
// NotACR.Token IS MyCRSpec.Token as far as CodeQL is concerned.
//
// It is never passed to SchemeBuilder.Register, so it is not a custom resource
// and nothing is reachable from it that is. The only thing keeping a write
// through a *NotACR out of the results is the base-type constraint in
// isCustomResourceFieldAccess (`owner = unwrap*(base.getType())`); wildcard
// that and noLeakUnregisteredStruct below is reported. The metav1 exclusion
// cannot save this one, because Token is not a metav1 field.
type NotACR struct {
	Token         string
	Ref           corev1.SecretKeySelector
	SecretHeaders []HeadersSource
	Slots         [2]PoolSlot
	PoolsByName   map[string][]PoolEntry
	NamedToken    TokenString
	RawToken      []byte
}

// MyCR is registered with the scheme below, which is what makes it a
// CustomResourceType as far as the query is concerned.
type MyCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec MyCRSpec
}

// SchemeBuilder registers MyCR. Without a real Register call, CustomResourceType
// is empty and this test proves nothing.
var SchemeBuilder = &scheme.Builder{}

func init() {
	SchemeBuilder.Register(&MyCR{})
}

// BAD: secret material is copied into a string field of a custom resource.
func leak(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Token = string(secret.Data["k"])
}

// GOOD: secret material is written to a promoted `metav1.ObjectMeta` field of
// a *Deployment*, which is not a custom resource.
//
// This is the ObjectMeta false positive. `ObjectMeta.Name` is one structural
// Field entity shared by MyCR, Deployment, Service, Pod and Secret alike, so
// with the write base wildcarded this was reported as a CR leak. It must not
// appear in .expected.
func noLeakDeploymentName(deployment *appsv1.Deployment, secret *corev1.Secret) {
	deployment.Name = string(secret.Data["k"])
}

// GOOD: the same write reached through the embedded ObjectMeta explicitly, so
// the write base really is metav1.ObjectMeta -- a type that IS reachable from
// MyCR. Only the "promoted from apimachinery meta/v1" exclusion rules this out.
func noLeakExplicitObjectMeta(deployment *appsv1.Deployment, secret *corev1.Secret) {
	deployment.ObjectMeta.Name = string(secret.Data["k"])
}

// GOOD: the write base is a *NotACR, an unregistered struct that happens to be
// structurally identical to MyCRSpec and so shares its Field entities. Nothing
// but the base-type constraint excludes it; see the NotACR doc comment.
func noLeakUnregisteredStruct(x *NotACR, secret *corev1.Secret) {
	x.Token = string(secret.Data["k"])
}

// BAD: secret material is copied into a string field that is only reachable
// through a slice member of the CR spec. This is the container-traversal case.
func leakNested(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.SecretHeaders[0].Value = string(secret.Data["k"])
}

// BAD: same, but the member is a fixed-size array. Exercises unwrap()'s
// ArrayType branch.
func leakNestedArray(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Slots[0].SlotValue = string(secret.Data["k"])
}

// BAD: same, but the member is a map whose value type carries the payload.
// Exercises unwrap()'s MapType branch (and the chaining in `unwrap*`).
func leakNestedMap(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.PoolsByName["pool"][0].EntryValue = string(secret.Data["k"])
}

// BAD: secret material is copied into a field whose type is a *named* string
// type. `StringType` is a BasicType and `TokenString` is a DefinedType, so this
// is only reported once the test goes through getUnderlyingType().
func leakNamedStringType(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.NamedToken = TokenString(secret.Data["k"])
}

// BAD: secret material is copied into a []byte field of the CR.
func leakByteSlice(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.RawToken = secret.Data["k"]
}

// BAD: the operator iterates the whole secret with `for k, v := range
// secret.Data` and copies a value into a string field of the CR. This is the
// range-over-Data case, and it is the shape real operators use most: there is
// no `secret.Data["k"]` index expression anywhere, so a source defined purely
// as `readsElement` on a `Secret.Data` read does not match it. The go library
// models the loop value as a `DataFlow::RangeElementNode` whose base is the
// `secret.Data` read; `DataFlow::readsAnElement` is the union of that and the
// index-expression form.
func leakRangeOverData(cr *MyCR, secret *corev1.Secret) {
	for key, val := range secret.Data {
		if key == "token" {
			cr.Spec.Token = string(val)
		}
	}
}

// BAD: the same loop over StringData, whose element type is already a string,
// so there is no conversion between source and sink.
func leakRangeOverStringData(cr *MyCR, secret *corev1.Secret) {
	for _, val := range secret.StringData {
		cr.Spec.Token = val
	}
}

// GOOD: only the *key* of the loop is used. A key of `Secret.Data` is a
// filename-like name, not secret material, so a range key must not become a
// source. This pins the RangeElementNode/RangeIndexNode distinction: matching
// the range statement's base rather than its element node would report this.
func noLeakRangeKeyOnly(cr *MyCR, secret *corev1.Secret) {
	for key := range secret.Data {
		cr.Spec.Token = key
	}
}
