package operator

import (
	"encoding/pem"

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
	// Fields is the map-element-write case. `cr.Spec.Fields[key] = v` produces
	// no field write at all -- only an element write -- so it is invisible to a
	// sink built solely on Write.writesField.
	Fields map[string]string
	// List is the append case. `cr.Spec.List = append(cr.Spec.List, v)` IS a
	// field write, but the node written is the *result of append*, typed
	// []string, so isStringishField never matches it and only
	// isStringishContainerField does.
	List []string
	// Template embeds a whole corev1.Secret in the spec, which real operators do
	// (kubeblocks). It is what makes corev1.Secret reachable from a registered CR
	// and therefore makes Secret.Data -- a map[string][]byte, and so a string-ish
	// container -- a "custom-resource field" as far as the sink is concerned.
	// Without this field the secret-to-secret fixtures below prove nothing.
	Template *corev1.Secret
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
	Fields        map[string]string
	List          []string
	Template      *corev1.Secret
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

// BAD: an element write into a map field of the CR spec. There is no field
// write here at all, so this is reported only once CustomResourceFieldSink
// grows a Write.writesElementPreUpdate branch.
func leakMapElementWrite(cr *MyCR, secret *corev1.Secret, key string) {
	cr.Spec.Fields[key] = string(secret.Data["k"])
}

// BAD: the same map reached through a local alias, which is why the container
// side of the sink is matched with DataFlow::localFlow rather than by requiring
// the write base to be the field read itself.
func leakMapElementWriteViaAlias(cr *MyCR, secret *corev1.Secret, key string) {
	fields := cr.Spec.Fields
	fields[key] = string(secret.Data["k"])
}

// BAD: append into a []string field of the CR spec. The written node is the
// result of `append`, whose type is []string, so isStringishField(List) is
// false and only isStringishContainerField makes this a sink.
func leakAppendToSlice(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.List = append(cr.Spec.List, string(secret.Data["k"]))
}

// BAD: a direct element write into the slice field, the non-append shape.
func leakSliceElementWrite(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.List[0] = string(secret.Data["k"])
}

// GOOD: an element write into a map[string]string that belongs to nothing.
// MyCRSpec.Fields is a map[string]string too, and Go gives both the same Type
// entity, so a sink that tested only the *type* of the write base would report
// this. Only the requirement that the container come from a custom-resource
// field read keeps it out.
func noLeakLocalMapElementWrite(secret *corev1.Secret, key string) map[string]string {
	m := map[string]string{}
	m[key] = string(secret.Data["k"])
	return m
}

// GOOD: an element write into the identically-shaped map of an unregistered
// struct. Same argument as noLeakUnregisteredStruct, for the element case.
func noLeakUnregisteredStructMap(x *NotACR, secret *corev1.Secret, key string) {
	x.Fields[key] = string(secret.Data["k"])
}

// BAD: secret material materialised as a literal environment-variable value in
// a PodSpec. corev1.EnvVar is not a custom-resource field and nothing in this
// file makes it reachable from MyCR, so this is reported only by
// SecretMaterializationSink -- exactly the kserve BuildSecretEnvs shape.
func leakEnvVarValue(pod *corev1.PodSpec, secret *corev1.Secret) {
	pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{
		Name:  "TOKEN",
		Value: string(secret.Data["k"]),
	})
}

// GOOD: the same environment variable built the safe way, as a reference to the
// secret rather than a copy of its contents. Nothing is materialised.
func noLeakEnvVarValueFrom(pod *corev1.PodSpec, secret *corev1.Secret) {
	pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{
		Name: "TOKEN",
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{Key: "k"},
		},
	})
}

// BAD: secret material written into a ConfigMap.Data entry -- an element write,
// the kubeblocks shape.
func leakConfigMapDataEntry(cm *corev1.ConfigMap, secret *corev1.Secret) {
	cm.Data["token"] = string(secret.Data["k"])
}

// BAD: the same ConfigMap built whole, as a map literal assigned to Data. Here
// the sink is the field write and the taint reaches the literal through its own
// element initialiser.
func leakConfigMapDataLiteral(secret *corev1.Secret) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		Data: map[string]string{"token": string(secret.Data["k"])},
	}
}

// BAD: secret material written into an annotation of a Deployment. Annotations
// are a metav1.ObjectMeta field, excluded from the custom-resource sink by
// isApiMachineryMetaField, and are matched here on their own terms.
func leakAnnotation(deployment *appsv1.Deployment, secret *corev1.Secret) {
	deployment.Annotations["token"] = string(secret.Data["k"])
}

// GOOD: tls.crt is the public half of a TLS keypair. Every client that opens a
// connection receives it, so copying it into a CR field is not a leak.
func noLeakTlsCertLiteralKey(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Token = string(secret.Data["tls.crt"])
}

// GOOD: the same key named through corev1.TLSCertKey. The exclusion compares
// constant *values*, so the named constant and the literal behave alike.
func noLeakTlsCertNamedConstant(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Token = string(secret.Data[corev1.TLSCertKey])
}

// GOOD: ca.crt, which is both the CA bundle of a TLS secret and the
// corev1.ServiceAccountRootCAKey entry of a service-account token secret.
func noLeakCaCert(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Token = string(secret.Data[corev1.ServiceAccountRootCAKey])
}

// BAD: tls.key is the private key and must stay a source. This is the fixture
// that stops the tls.crt exclusion from being widened to the whole TLS secret.
func leakTlsPrivateKey(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Token = string(secret.Data[corev1.TLSPrivateKeyKey])
}

// GOOD: pem.Block.Type is the PEM label -- the literal "CERTIFICATE" or "RSA
// PRIVATE KEY" -- not key material.
//
// It has to be suppressed explicitly because two library behaviours combine
// against it. encoding/pem.Decode carries a manual MaD summary, taint from
// Argument[0] to ReturnValue[0..1], so the whole *pem.Block is plainly tainted
// -- with no content qualifier -- by the private key that was decoded. Reading
// any field of a plainly tainted struct is then tainted in turn, because the go
// taint library's fieldReadStep is field-insensitive. So the label comes out
// tainted and lands in the CR.
//
// The construction must be a Decode call, not a `&pem.Block{...}` literal: a
// literal stores into the Bytes *content*, content-precise flow keeps it there,
// and no taint ever reaches the Type field. Writing the fixture that way makes
// it pass no matter what the library says (verified: it survived removing the
// sanitizer entirely).
func noLeakPemBlockType(cr *MyCR, secret *corev1.Secret) {
	block, _ := pem.Decode(secret.Data[corev1.TLSPrivateKeyKey])
	cr.Spec.Token = block.Type
}

// BAD: the decoded private key itself, read out of the same block. This is the
// control for noLeakPemBlockType: the suppression must be scoped to the label
// field and must not sanitise the decoded block as a whole.
func leakPemBlockBytes(cr *MyCR, secret *corev1.Secret) {
	block, _ := pem.Decode(secret.Data[corev1.TLSPrivateKeyKey])
	cr.Spec.RawToken = block.Bytes
}

// GOOD: secret material copied from one Secret into another Secret. This is the
// single largest FP class the element-write sink opens up: on kubeblocks it
// accounts for twelve results on its own (`proto.Data[k] = secret.Data[k]`,
// `runningCopy.Data[k] = ...`, `builder.get().Data = data`). A Secret is where
// secret material belongs, so Secret.Data and Secret.StringData are excluded as
// destinations. MyCRSpec.Template is what puts corev1.Secret inside the CR type
// graph, which is what makes this reachable at all.
func noLeakSecretToSecretElement(dst *corev1.Secret, secret *corev1.Secret, key string) {
	dst.Data[key] = secret.Data["k"]
}

// GOOD: the same copy done as a whole-map field write -- kubeblocks'
// SecretBuilder.PutData, verbatim in shape. The element write taints the local
// map, and the map is then assigned to Secret.Data as a whole, so this exercises
// the *field-write* half of the Secret exclusion. Writing it the obvious way,
// `dst.Data = secret.Data`, would prove nothing: reading a whole Data map is not
// a source, only reading an element of one is, so no taint would ever arrive.
func noLeakSecretToSecretBuilder(dst *corev1.Secret, secret *corev1.Secret, key string) {
	data := dst.Data
	if data == nil {
		data = make(map[string][]byte, 1)
	}
	data[key] = secret.Data["k"]
	dst.Data = data
}

// GOOD: and into StringData, the other half of the exclusion.
func noLeakSecretToSecretStringData(dst *corev1.Secret, secret *corev1.Secret, key string) {
	dst.StringData[key] = string(secret.Data["k"])
}

// MIXED: the control for the three above. The first write goes into the
// StringData of a Secret that is *itself a field of the custom resource*, and is
// still excused -- the exclusion is about the destination field, not about who
// owns the Secret. The second write, in the same function and from the same
// source, goes into an ordinary CR string field and MUST still be reported: the
// exclusion must be scoped to Secret.Data/StringData and must not sanitise the
// source, the secret, or the enclosing function.
func leakIntoCrFieldFromSecretTemplate(cr *MyCR, secret *corev1.Secret) {
	cr.Spec.Template.StringData["k"] = string(secret.Data["k"])
	cr.Spec.Token = string(secret.Data["k"])
}

// envTokenName is the environment-variable name the three fixtures below switch
// on. A named constant rather than a literal, because that is how operators
// write the check (`if envVar.Name == s3.AWSCABundle`) and because the barrier
// deliberately does not require the compared-against operand to be constant at
// all -- see envVarNameEqualityGuard.
const envTokenName = "TOKEN"

// buildSecretEnv materialises secret material as a literal environment-variable
// value: the kserve BuildSecretEnvs shape, and a SecretMaterializationSink in
// its own right, so the write on the Value line below is reported.
//
// It exists so that the three fixtures that follow are identical in every
// respect except their guard. Each of them ranges over this slice, so real
// secret taint arrives at their `e.Value` read; the only thing that can stop it
// reaching the custom resource is guardedEnvVarValueRead. Without a shared
// builder the negative control would not be a control at all -- it would differ
// from the guarded cases in how the taint got there as well as in the guard.
func buildSecretEnv(secret *corev1.Secret) []corev1.EnvVar {
	return []corev1.EnvVar{{
		Name:  envTokenName,
		Value: string(secret.Data["k"]),
	}}
}

// GOOD: the value is read back out of the environment under an equality check on
// the corresponding Name, so the read is a guardedEnvVarValueRead and the flow
// into the CR field is cut.
//
// This is the `if` half of the barrier, and it is a distinct code path from the
// `switch` half below: the check produces a ControlFlow::ConditionGuardNode
// whose true-successor dominates the basic block of the Value read
// (envVarNameEqualityGuard + ConditionGuardNode.dominates). Delete that disjunct
// and this function is reported.
func noLeakGuardedEnvVarIfRead(cr *MyCR, secret *corev1.Secret) {
	for _, e := range buildSecretEnv(secret) {
		if e.Name == envTokenName {
			cr.Spec.Token = e.Value
		}
	}
}

// GOOD: the same read under a *tagged* switch on Name.
//
// This is the `switch` half of the barrier. A tagged switch produces no
// ConditionGuardNode at all -- condition guards are built only for boolean
// branch conditions, and a tagged switch's case expressions are values -- so the
// `if` disjunct cannot cover this shape and envVarNameSwitchCaseEntry
// (ControlFlow::isSwitchCaseTestPassingEdge + basic-block dominance) is what
// cuts it. Delete that disjunct and this function is reported.
func noLeakGuardedEnvVarSwitchRead(cr *MyCR, secret *corev1.Secret) {
	for _, e := range buildSecretEnv(secret) {
		switch e.Name {
		case envTokenName:
			cr.Spec.Token = e.Value
		}
	}
}

// BAD, and this is the negative control for the two fixtures above: the same
// loop over the same builder, writing the same field, with no check on Name.
// Nothing correlates this Value with any particular EnvVar, so the read is not
// barriered and the leak must still be reported.
//
// Without this fixture the two GOOD cases prove nothing: a barrier that
// sanitised *every* read of EnvVar.Value -- or a query that had lost the flow
// through this shape entirely -- would pass them both.
func leakUnguardedEnvVarRead(cr *MyCR, secret *corev1.Secret) {
	for _, e := range buildSecretEnv(secret) {
		cr.Spec.Token = e.Value
	}
}
