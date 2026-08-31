// Package operator is the fixture for the table-driven scheme-registration
// idiom -- the shape in which a custom resource's concrete type is named exactly
// once, in a composite literal, and reaches the scheme as a bare runtime.Object.
//
// velero is the operator this is reduced from (pkg/apis/velero/v1/register.go).
// Under the two syntactic disjuncts of CustomResourceType, which read the
// concrete type straight off the registration call's argument
// (`ce.getAnArgument().getType().(PointerType).getBaseType()`), velero resolves
// ZERO custom resource types: at the call the argument's static type is the
// interface runtime.Object, and an interface is not a PointerType. With no CR
// types there are no CR-field sinks, so both security queries report a vacuous
// zero on it. The third disjunct, backed by SchemeRegistrationFlow, is what
// closes that; this directory is what holds it closed.
//
// Two queries run over this one database:
//
//   - CustomResourceTypes.ql lists CustomResourceType by package and name. It is
//     the direct assertion: the four positives are present, the five negatives
//     are absent, and the package column is what makes the k8s.io/ exclusion
//     visible -- without it, Secret being absent could not be told apart from
//     Secret never having been a candidate.
//   - K8sSecretsLeak.qlref is the consequence assertion. Being a CustomResourceType
//     is only interesting because it turns the type's fields into sinks, so each
//     positive CR here also has secret material written into a field of it, and
//     each negative has the *same* write into a structurally identical field.
//     Whether a write is reported is therefore decided by nothing but the
//     registration shape that reaches its type.
//
// The negatives are the point of the file. Four of the five are what stops the
// flow disjunct from turning every Kubernetes-object-shaped struct in a
// repository into a custom resource; the fifth pins a known miss. Each is aimed
// at one specific guard:
//
//	unregisteredTable  -> reachability: the flow requirement itself
//	addUpstreamType    -> the k8s.io/ package exclusion in isRegisterableApiObjectType
//	addNoObjectMeta    -> the ObjectMeta/ListMeta half of the structural filter
//	addNoTypeMeta      -> the TypeMeta half of the structural filter
//	addVarAddress      -> the composite-literal restriction in isApiObjectLiteral
//
// Each of those five was checked by mutation: delete the guard it names from
// K8sOperators.qll and this suite goes red on that case and on nothing else.
// The first three were the cases originally asked for. The last two are here
// because deleting their guards left the suite GREEN on the first draft of this
// fixture, which is the same thing as saying they were untested.
package operator

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// SchemeGroupVersion is velero's, reduced. It is the first argument of every
// AddKnownTypes call below, and so is a sink of SchemeRegistrationConfig -- one
// that no API-object literal can reach, which is the whole reason the
// configuration can afford to treat every argument as a sink.
var SchemeGroupVersion = schema.GroupVersion{Group: "example.com", Version: "v1"}

// ---------------------------------------------------------------------------
// (a) The full velero chain.
//
// &MyCR{} -> helper function taking runtime.Object -> struct field -> map
// literal -> return across a function boundary -> range -> field read ->
// AddKnownTypes. Five of the six links are things DataFlow::localFlow cannot
// follow, and two of them (the store into typeInfo.ItemType and the matching
// read after the range) are content steps, which is why this needs a global
// configuration with store/read support rather than a hand-written local step.
//
// This is copied structurally from velero rather than shortened, because a
// shortened fixture would go green while the real shape still failed.
// ---------------------------------------------------------------------------

// MyCRSpec is the spec half of the table-driven custom resource.
type MyCRSpec struct {
	// Token is written to by leakIntoMyCR. It is a CustomResourceFieldSink
	// only because MyCR is resolved as a CustomResourceType.
	Token string
}

// MyCR is registered through the full velero chain.
type MyCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec MyCRSpec
}

// MyCRList is the list type of MyCR. It embeds ListMeta rather than ObjectMeta,
// which is the other half of isRegisterableApiObjectType's structural filter,
// and it is deliberately expected to be a CustomResourceType in its own right:
// kubebuilder's SchemeBuilder.Register(&Foo{}, &FooList{}) has always made both
// disjuncts admit list types, and having the flow disjunct disagree would make
// the same operator report different numbers depending on which idiom it used.
type MyCRList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []MyCR
}

// typeInfo is velero's typeInfo verbatim. ItemType and ItemListType are typed
// runtime.Object, so the concrete type is erased on the way in and the store
// into these fields is the content step the chain turns on.
type typeInfo struct {
	PluralName   string
	ItemType     runtime.Object
	ItemListType runtime.Object
}

// newTypeInfo is velero's newTypeInfo verbatim: the function boundary that
// widens *MyCR to runtime.Object.
func newTypeInfo(pluralName string, itemType, itemListType runtime.Object) typeInfo {
	return typeInfo{PluralName: pluralName, ItemType: itemType, ItemListType: itemListType}
}

// CustomResources is velero's CustomResources, reduced to one entry. The map
// literal and the return are two more boundaries between the literal and the
// registration call.
func CustomResources() map[string]typeInfo {
	return map[string]typeInfo{
		"MyCR": newTypeInfo("mycrs", &MyCR{}, &MyCRList{}),
	}
}

// addKnownTypes is velero's addKnownTypes verbatim. Note that neither MyCR nor
// MyCRList is named anywhere in this function: the arguments are typed
// runtime.Object, which is what makes the syntactic disjuncts blind here.
func addKnownTypes(scheme *runtime.Scheme) error {
	for _, info := range CustomResources() {
		scheme.AddKnownTypes(SchemeGroupVersion, info.ItemType, info.ItemListType)
	}
	return nil
}

// ---------------------------------------------------------------------------
// (b) The short variant: literal -> local variable typed runtime.Object -> call.
//
// No content step and no function boundary, only the widening to the interface.
// It is here because it is the minimum the syntactic disjuncts already fail on:
// if this one alone were the fixture, an implementation that handled nothing but
// a local assignment would pass.
// ---------------------------------------------------------------------------

// ShortCRSpec is the spec half of the short-variant custom resource.
type ShortCRSpec struct {
	// Token is written to by leakIntoShortCR.
	Token string
}

// ShortCR is registered through a local variable typed runtime.Object.
type ShortCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec ShortCRSpec
}

// addShortChain registers ShortCR without ever naming *ShortCR at the call.
func addShortChain(scheme *runtime.Scheme) {
	var obj runtime.Object = &ShortCR{}
	scheme.AddKnownTypes(SchemeGroupVersion, obj)
}

// ---------------------------------------------------------------------------
// (c) The slice-based table: []runtime.Object{...} ranged over into the call.
//
// The same erasure as (a) but through a slice's element content rather than a
// struct field and a map value.
// ---------------------------------------------------------------------------

// SliceCRSpec is the spec half of the slice-table custom resource.
type SliceCRSpec struct {
	// Token is written to by leakIntoSliceCR.
	Token string
}

// SliceCR is registered by ranging over a []runtime.Object.
type SliceCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec SliceCRSpec
}

// SliceCRList is the list type of SliceCR, registered from the same slice.
type SliceCRList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []SliceCR
}

// addSliceTable registers both SliceCR and SliceCRList out of one slice literal.
func addSliceTable(scheme *runtime.Scheme) {
	for _, obj := range []runtime.Object{&SliceCR{}, &SliceCRList{}} {
		scheme.AddKnownTypes(SchemeGroupVersion, obj)
	}
}

// ---------------------------------------------------------------------------
// (d) The same slice table, but through kubebuilder's scheme.Builder.Register
// rather than runtime.Scheme.AddKnownTypes.
//
// isSchemeRegistrationArgument treats both call targets as sinks --
// SchemaBuilder (controller-runtime) and APISchemaBuilder (apimachinery) -- and
// nothing else in this directory exercised the first one. Deleting the
// SchemaBuilder half of that disjunct left the suite green, so this case exists
// to close that. The shape is real: an operator that keeps its kinds in a table
// and loops SchemeBuilder.Register over it erases the concrete type exactly the
// way the AddKnownTypes operators do, and the syntactic disjuncts are just as
// blind to it.
// ---------------------------------------------------------------------------

// BuilderCRSpec is the spec half of the kubebuilder-registered custom resource.
type BuilderCRSpec struct {
	// Token is written to by leakIntoBuilderCR.
	Token string
}

// BuilderCR is registered by flowing into scheme.Builder.Register.
type BuilderCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec BuilderCRSpec
}

// SchemeBuilder is the kubebuilder package-level builder.
var SchemeBuilder = &scheme.Builder{}

// registerBuilderTable loops the builder over a table instead of naming the
// types at the call.
func registerBuilderTable() {
	for _, obj := range []runtime.Object{&BuilderCR{}} {
		SchemeBuilder.Register(obj)
	}
}

// ---------------------------------------------------------------------------
// (e) NEGATIVE -- reachability. Built exactly like (a) and never registered.
//
// NotACR is indistinguishable from MyCR by inspection: same embeds, same spec
// shape, same helper, same struct field, same map literal, same range. The one
// difference is that the map it lands in is consumed by describeUnregistered
// instead of by AddKnownTypes.
//
// It shares newTypeInfo and typeInfo with the registered chain on purpose. A
// negative built on its own private helper would only prove that two unrelated
// chains do not interfere; sharing the helper asserts that the configuration
// distinguishes the two *call sites* of newTypeInfo, which is the property that
// would actually break if flow through the helper were summarised
// context-insensitively.
// ---------------------------------------------------------------------------

// NotACRSpec is shaped exactly like MyCRSpec.
type NotACRSpec struct {
	// Token is written to by leakIntoNotACR -- the same write as leakIntoMyCR,
	// into a structurally identical field, and it must NOT be reported.
	Token string
}

// NotACR has every structural mark of a custom resource and is never registered.
type NotACR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec NotACRSpec
}

// NotACRList is the list type of NotACR, equally unregistered.
type NotACRList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []NotACR
}

// unregisteredTable is CustomResources' twin, down to the shared helper.
func unregisteredTable() map[string]typeInfo {
	return map[string]typeInfo{
		"NotACR": newTypeInfo("notacrs", &NotACR{}, &NotACRList{}),
	}
}

// describeUnregistered consumes the table the way addKnownTypes consumes the
// registered one -- a range and a field read -- but ends at a string slice
// rather than at a scheme.
func describeUnregistered() []string {
	var names []string
	for _, info := range unregisteredTable() {
		names = append(names, info.PluralName)
	}
	return names
}

// ---------------------------------------------------------------------------
// (f) NEGATIVE -- the k8s.io/ package exclusion.
//
// corev1.Secret is registered through the same erasing local variable as (b).
// The stub Secret embeds TypeMeta and ObjectMeta exactly as the real one does,
// so it satisfies the structural filter completely and the ONLY thing that keeps
// it out of CustomResourceType is the package exclusion in
// isRegisterableApiObjectType.
//
// This is not a contrived shape. Upstream packages really do register their own
// types with a scheme, and admitting them would make corev1.Secret a custom
// resource -- which in this pack means every write into Secret.Data becomes a
// leak sink and the secret-leak query starts reporting secret-to-secret copies.
// copySecret below is that consequence, held at zero.
// ---------------------------------------------------------------------------

// addUpstreamType registers an upstream k8s.io/ type through the erasing path.
func addUpstreamType(scheme *runtime.Scheme) {
	var obj runtime.Object = &corev1.Secret{}
	scheme.AddKnownTypes(SchemeGroupVersion, obj)
}

// NOT reported: an operator deriving one Secret's type from another's contents.
//
// Reading src.Data is a K8sSecretData source, and the write into dst.Type is a
// CustomResourceFieldSink if and only if corev1.Secret is part of a custom
// resource -- which is exactly what the k8s.io/ exclusion prevents. Removing the
// exclusion makes this a finding, and with it every write into a plain field of
// any upstream API object the operator touches.
//
// The destination is Type and not Data on purpose. Data and StringData are
// K8sSecretDataFields, and isCustomResourceStringishContainer excludes those by
// name (`not f instanceof K8sSecretDataField`), so `dst.Data[k] = src.Data[k]`
// stays silent even with Secret wrongly admitted -- copying secret material into
// another Secret is not a leak, and the library says so deliberately. A fixture
// written against Data would therefore assert nothing at all: it was, and it
// did, until mutation m3 left this query green and exposed it.
func copySecret(dst, src *corev1.Secret) {
	dst.Type = corev1.SecretType(src.Data["type"])
}

// ---------------------------------------------------------------------------
// (g) NEGATIVE -- the ObjectMeta/ListMeta half of the structural filter.
//
// NoObjectMetaCR embeds TypeMeta but neither ObjectMeta nor ListMeta, so it
// cannot be a top-level API object: without ObjectMeta it has no name and no
// namespace and the API server has nothing to address it by. The implementation
// requires TypeMeta AND one of the two, so it must not be admitted.
//
// It reaches AddKnownTypes through the *erasing* path rather than as a direct
// &NoObjectMetaCR{} argument, and that is deliberate. Passed directly it would
// be admitted -- by the second syntactic disjunct, which tests only the package
// path and not the structure -- and the fixture would then be asserting the
// opposite of what it means to. The structural filter constrains the flow
// disjunct only; see the report accompanying this suite.
// ---------------------------------------------------------------------------

// NoObjectMetaCRSpec is shaped exactly like MyCRSpec.
type NoObjectMetaCRSpec struct {
	// Token is written to by leakIntoNoObjectMeta, and must NOT be reported.
	Token string
}

// NoObjectMetaCR embeds TypeMeta only.
type NoObjectMetaCR struct {
	metav1.TypeMeta
	Spec NoObjectMetaCRSpec
}

// addNoObjectMeta pushes a structurally ineligible type at the scheme through
// the same erasing local variable that (b) is registered by.
func addNoObjectMeta(scheme *runtime.Scheme) {
	var obj runtime.Object = &NoObjectMetaCR{}
	scheme.AddKnownTypes(SchemeGroupVersion, obj)
}

// ---------------------------------------------------------------------------
// (h) NEGATIVE -- the TypeMeta half of the structural filter.
//
// NoTypeMetaCR embeds ObjectMeta but not TypeMeta, so it has a name and a
// namespace but carries no apiVersion/kind and cannot be serialised as a
// standalone API object. isRegisterableApiObjectType requires TypeMeta AND one
// of ObjectMeta/ListMeta, and this is the AND's other operand.
//
// It is not a shape anyone would write on purpose at a registration call, and
// that is exactly why it needed a fixture: the ObjectMeta-only struct is
// extremely common in real operators (corev1.PodTemplateSpec is one, and an
// operator constructs those by the hundred), so the TypeMeta conjunct is doing
// real work bounding the source set even though no real operator registers such
// a type. Deleting that conjunct changed no result at all until this case
// existed.
// ---------------------------------------------------------------------------

// NoTypeMetaCRSpec is shaped exactly like MyCRSpec.
type NoTypeMetaCRSpec struct {
	// Token is written to by leakIntoNoTypeMeta, and must NOT be reported.
	Token string
}

// NoTypeMetaCR embeds ObjectMeta only.
type NoTypeMetaCR struct {
	metav1.ObjectMeta
	Spec NoTypeMetaCRSpec
}

// addNoTypeMeta pushes it at the scheme through the erasing local variable.
func addNoTypeMeta(scheme *runtime.Scheme) {
	var obj runtime.Object = &NoTypeMetaCR{}
	scheme.AddKnownTypes(SchemeGroupVersion, obj)
}

// ---------------------------------------------------------------------------
// (i) NEGATIVE -- the composite-literal restriction, and a known recall limit.
//
// isApiObjectLiteral requires the operand of the & to be a CompositeLit, so
// `&varAddrCR` -- the address of a package-level variable -- is not a source and
// VarAddrCR is not resolved here.
//
// Unlike the other negatives this one is NOT a precision win. VarAddrCR really
// is registered with the scheme, and the pack really does miss it. The
// CustomResourceType QLDoc says the syntactic disjuncts still cover "a
// package-level `var backup Backup` passed as `&backup`", and they do -- but
// only when it is passed *directly*, where its static type is still *VarAddrCR.
// Routed through the erasing path, as here, neither the syntactic disjuncts nor
// the flow disjunct sees it and the registration is lost. This case pins that
// gap rather than hiding it: the expected output is what the implementation
// currently does, and if someone widens isApiObjectLiteral to cover it this test
// is where they will find out they succeeded.
// ---------------------------------------------------------------------------

// VarAddrCRSpec is shaped exactly like MyCRSpec.
type VarAddrCRSpec struct {
	// Token is written to by leakIntoVarAddr. It is NOT reported today, and
	// that is a false negative rather than a desired outcome.
	Token string
}

// VarAddrCR is genuinely registered, and genuinely missed.
type VarAddrCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec VarAddrCRSpec
}

// varAddrCR is deliberately declared without a composite literal anywhere, so
// that the absence is attributable to the CompositeLit restriction alone and not
// to flow failing to reach some literal elsewhere.
var varAddrCR VarAddrCR

// addVarAddress registers the address of that variable.
func addVarAddress(scheme *runtime.Scheme) {
	var obj runtime.Object = &varAddrCR
	scheme.AddKnownTypes(SchemeGroupVersion, obj)
}

// ---------------------------------------------------------------------------
// The consequence assertions: eight identical writes of secret material into
// eight structurally identical string fields. Four are reported and four are
// not, and the only thing that differs is how the destination type reached -- or
// failed to reach -- a scheme.
// ---------------------------------------------------------------------------

// BAD, and reported: MyCR is registered through the full velero chain.
func leakIntoMyCR(secret *corev1.Secret, cr *MyCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// BAD, and reported: ShortCR is registered through a local runtime.Object.
func leakIntoShortCR(secret *corev1.Secret, cr *ShortCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// BAD, and reported: SliceCR is registered out of a []runtime.Object table.
func leakIntoSliceCR(secret *corev1.Secret, cr *SliceCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// BAD, and reported: BuilderCR reaches scheme.Builder.Register through a table.
func leakIntoBuilderCR(secret *corev1.Secret, cr *BuilderCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// NOT reported: NotACR is never registered, so its fields are not sinks.
func leakIntoNotACR(secret *corev1.Secret, cr *NotACR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// NOT reported: NoObjectMetaCR is not a registerable API object.
func leakIntoNoObjectMeta(secret *corev1.Secret, cr *NoObjectMetaCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// NOT reported: NoTypeMetaCR is not a registerable API object.
func leakIntoNoTypeMeta(secret *corev1.Secret, cr *NoTypeMetaCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// NOT reported, and this one is a MISS rather than a correct silence: VarAddrCR
// is registered, but through &variable rather than &Literal{}. See addVarAddress.
func leakIntoVarAddr(secret *corev1.Secret, cr *VarAddrCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// keepUsed exists so that every registration entry point is called from
// somewhere in the package. Nothing in the pack depends on reachability from a
// main function, but an unused private function is a smell in a fixture that
// claims to reproduce a real registration file.
func keepUsed(scheme *runtime.Scheme) {
	_ = addKnownTypes(scheme)
	addShortChain(scheme)
	addSliceTable(scheme)
	addUpstreamType(scheme)
	addNoObjectMeta(scheme)
	addNoTypeMeta(scheme)
	addVarAddress(scheme)
	registerBuilderTable()
	_ = describeUnregistered()
}
