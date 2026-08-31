/**
 * Shared definitions for reasoning about Kubernetes operators written in Go:
 * how custom resource types are registered with a scheme, how Kubernetes
 * `Secret` values are read, and which fields of a custom resource are
 * interesting as taint sources or sinks.
 *
 * This library sits at the root of the pack, so queries import it as
 * `import K8sOperators`.
 */

import go

/**
 * The `Register` function of `sigs.k8s.io/controller-runtime/pkg/scheme`,
 * which an operator calls (usually via a package-level `SchemeBuilder`) to
 * register its custom resource types with the runtime scheme.
 */
class SchemaBuilder extends Function {
  SchemaBuilder() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme" and
    this.getName() = "Register"
  }
}

/**
 * The `AddKnownTypes` / `AddKnownTypeWithName` methods of
 * `k8s.io/apimachinery/pkg/runtime.Scheme`: the client-go / code-generator way
 * of registering API types with a scheme, used by operators that predate
 * kubebuilder (cert-manager, zalando/postgres-operator).
 *
 * These are methods on `*runtime.Scheme`, so this must be a `Method` pinned by
 * `hasQualifiedName` rather than a bare `Function` name match. Note also that
 * `getReceiverType().getName()` has no result for a pointer receiver — use
 * `getReceiverBaseType()` if you ever need the receiver by name.
 */
class APISchemaBuilder extends Method {
  APISchemaBuilder() {
    this.hasQualifiedName("k8s.io/apimachinery/pkg/runtime", "Scheme",
      ["AddKnownTypes", "AddKnownTypeWithName"])
  }
}

/**
 * Holds if `t` embeds the apimachinery meta struct named `name` — one of
 * `TypeMeta`, `ObjectMeta` or `ListMeta`.
 *
 * The test is for a *field whose own type is* `metav1.<name>`, which in Go is
 * exactly what an embedded field looks like: `metav1.TypeMeta` embedded in
 * `Backup` is a field named `TypeMeta` of type `metav1.TypeMeta`.
 *
 * `Type.getField` also returns promoted fields — asking velero's `Backup` for
 * its fields yields `Kind`, `Namespace`, `Labels` and the rest of `ObjectMeta`
 * alongside `Spec` and `Status` — so this holds for a type that embeds the meta
 * struct at any depth, not only directly. That is the intended reading: a struct
 * that reaches `TypeMeta` through an embedded struct is still a Kubernetes API
 * object. It does *not* hold merely because a type has a named (non-embedded)
 * field of some other struct type, because promotion follows embedding only.
 */
private predicate embedsApiMachineryMeta(Type t, string name) {
  exists(Field f |
    f = t.getField(_) and
    f.getType().hasQualifiedName("k8s.io/apimachinery/pkg/apis/meta/v1", name)
  )
}

/**
 * Holds if `t` has the structural signature of a top-level Kubernetes API object
 * declared by the operator under analysis: it embeds `metav1.TypeMeta` together
 * with either `metav1.ObjectMeta` (an item, `Backup`) or `metav1.ListMeta` (a
 * list, `BackupList`), and it is not declared under `k8s.io/` or `sigs.k8s.io/`.
 *
 * This is the source filter for `SchemeRegistrationFlow`, and it is what makes
 * that configuration affordable. A composite literal `&T{}` is one of the most
 * common expressions in Go — 1836 of them in velero, 2139 in cert-manager — and
 * seeding a global data-flow configuration with all of them is not viable. The
 * signature cuts that to 255 and 168 respectively. It costs no recall, because
 * embedding `TypeMeta` plus one of the two metas is not a heuristic: it is the
 * contract an object must satisfy to implement `runtime.Object` and be
 * registerable with a scheme at all.
 *
 * The package exclusion is applied here, at the source, rather than to the type
 * that comes out. It is the same exclusion the `AddKnownTypes` disjunct of
 * `CustomResourceType` carries — upstream packages register their own types,
 * `corev1.Secret` included, and admitting them would make `Secret` itself a
 * custom resource — but flow reaches further than a syntactic argument match, so
 * with flow it matters more, not less. Excluding upstream literals from the
 * search space is both cheaper and safer than filtering the answer afterwards.
 */
private predicate isRegisterableApiObjectType(Type t) {
  embedsApiMachineryMeta(t, "TypeMeta") and
  embedsApiMachineryMeta(t, ["ObjectMeta", "ListMeta"]) and
  exists(string pkg |
    t.hasQualifiedName(pkg, _) and
    not pkg.matches(["k8s.io/%", "sigs.k8s.io/%"])
  )
}

/**
 * Holds if `n` is the expression `&T{}`, a pointer to a freshly constructed
 * Kubernetes API object whose type is `base`.
 */
private predicate isApiObjectLiteral(DataFlow::Node n, Type base) {
  exists(AddressExpr addr |
    n.asExpr() = addr and
    addr.getOperand() instanceof CompositeLit and
    base = addr.getOperand().getType() and
    isRegisterableApiObjectType(base)
  )
}

/**
 * Holds if `n` is an argument of a call that registers types with a runtime
 * scheme: `scheme.Builder.Register`, `runtime.Scheme.AddKnownTypes` or
 * `runtime.Scheme.AddKnownTypeWithName`.
 *
 * Every argument is a sink, not just the object ones. The non-object arguments
 * are a `schema.GroupVersion` and a kind string, neither of which any API-object
 * literal can flow to, so narrowing by position would buy nothing and would have
 * to be kept in step with three different signatures.
 */
private predicate isSchemeRegistrationArgument(DataFlow::Node n) {
  exists(CallExpr ce |
    ce.getTarget() instanceof SchemaBuilder or
    ce.getTarget() instanceof APISchemaBuilder
  |
    n.asExpr() = ce.getAnArgument()
  )
}

/**
 * Value flow from an API-object literal `&T{}` to an argument of a scheme
 * registration call.
 *
 * This exists for the *table-driven* registration idiom, in which the concrete
 * type never appears at the registration call at all. velero is the canonical
 * example (`pkg/apis/velero/v1/register.go`):
 *
 * ```go
 * type typeInfo struct{ PluralName string; ItemType, ItemListType runtime.Object }
 *
 * func newTypeInfo(pluralName string, itemType, itemListType runtime.Object) typeInfo {
 *   return typeInfo{PluralName: pluralName, ItemType: itemType, ItemListType: itemListType}
 * }
 *
 * func CustomResources() map[string]typeInfo {
 *   return map[string]typeInfo{
 *     "Backup":  newTypeInfo("backups", &Backup{}, &BackupList{}),
 *     "Restore": newTypeInfo("restores", &Restore{}, &RestoreList{}),
 *     // ... 11 entries
 *   }
 * }
 *
 * func addKnownTypes(scheme *runtime.Scheme) error {
 *   for _, typeInfo := range CustomResources() {
 *     scheme.AddKnownTypes(SchemeGroupVersion, typeInfo.ItemType, typeInfo.ItemListType)
 *   }
 * }
 * ```
 *
 * `Backup` is named exactly once in the whole registration, in the composite
 * literal `&Backup{}`. From there it is widened to the interface
 * `runtime.Object` by `newTypeInfo`'s parameter, stored into a struct field,
 * placed in a map literal, returned across a function boundary, read back out by
 * a `range`, and only then passed to `AddKnownTypes`. By the time it reaches the
 * call its static type is `runtime.Object`, so the syntactic match
 * `ce.getAnArgument().getType().(PointerType).getBaseType()` used by the other
 * two disjuncts of `CustomResourceType` resolves nothing at all. velero reports
 * **zero** custom resource types under that match — and with no CR types there
 * are no CR-field sinks, so both security queries report a vacuous zero on it
 * rather than a real one.
 *
 * The chain crosses a helper function, a struct-field store, a map literal and a
 * range read, so `DataFlow::localFlow` cannot span it even with a hand-written
 * step for the helper call: the store into `typeInfo.ItemType` and the matching
 * read after the `range` are content steps, and content is what local flow does
 * not have. Interprocedural flow with store/read steps is the smallest thing
 * that works, which is `DataFlow::Global`.
 *
 * `DataFlow::Global` and not `TaintTracking::Global`, for two reasons. What is
 * being tracked is the *identity* of an object, so taint's extra steps — string
 * operations, calls that merely observe a value — could let one registered
 * type's identity bleed onto another and would buy nothing here. And a
 * `DataFlow::Global` configuration is not subject to
 * `TaintTracking::DefaultTaintSanitizer`, so this configuration is insulated
 * from `PemBlockTypeSanitizer` and from any other pack-wide taint barrier; none
 * of them has anything to say about scheme registration, and inheriting them
 * silently would be a bug waiting to happen.
 *
 * This is the third data-flow configuration in the pack and the only one that
 * lives in the library rather than in a query. It is `private`, so it cannot
 * collide with `SecretToCrConfig` in `K8sSecretsLeak.ql` or `CrToSqlConfig` in
 * `K8sCustomResourceSqlInjection.ql`, and neither of those inherits anything
 * from it.
 */
private module SchemeRegistrationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { isApiObjectLiteral(n, _) }

  predicate isSink(DataFlow::Node n) { isSchemeRegistrationArgument(n) }
}

private module SchemeRegistrationFlow = DataFlow::Global<SchemeRegistrationConfig>;

/**
 * A type registered as a Kubernetes custom resource: the base type of a pointer
 * passed either to `scheme.Builder.Register` (the kubebuilder idiom) or to
 * `runtime.Scheme.AddKnownTypes` / `AddKnownTypeWithName` (the client-go idiom).
 *
 * Both idioms are needed: they split the operator ecosystem roughly in half, and
 * matching only the first returns zero CR types — and therefore zero results —
 * on every operator that predates kubebuilder.
 *
 * Upstream Kubernetes API packages register their own types (including
 * `corev1.Secret`) through the second form, so types declared under `k8s.io/` or
 * `sigs.k8s.io/` are excluded by package path rather than by dropping the whole
 * idiom.
 *
 * The first two disjuncts read the concrete type straight off the call argument.
 * They are the fast path and they cover most operators, but they see only the
 * case where the type is written *at* the registration call. The third disjunct
 * covers the table-driven idiom, where it is not: the type is named once in a
 * composite literal and reaches the scheme through a helper function, a struct
 * field and a map, arriving as a bare `runtime.Object`. See
 * `SchemeRegistrationFlow` for the shape and for why local reasoning cannot span
 * it. Keeping the syntactic disjuncts rather than letting flow subsume them is
 * deliberate: they cost almost nothing, and they still match registrations whose
 * argument is not a composite literal at all (a package-level `var backup Backup`
 * passed as `&backup`, say), which the flow disjunct's source filter excludes.
 *
 * List types (`BackupList`) count as custom resource types. That is not a new
 * decision made here — kubebuilder's `SchemeBuilder.Register(&Foo{}, &FooList{})`
 * passes both, so the syntactic disjuncts have always admitted both, and having
 * the flow disjunct disagree would make the same operator report different
 * numbers depending on which idiom it happened to use. It is also a distinction
 * without a difference for the queries downstream: a list's `Items []Foo` field
 * makes `Foo` reachable through `isPartOfCustomResource` either way. Concretely,
 * velero's 13 kinds across two API versions yield 26 types, item and list.
 */
class CustomResourceType extends Type {
  CustomResourceType() {
    exists(CallExpr ce |
      ce.getTarget() instanceof SchemaBuilder and
      this = ce.getAnArgument().getType().(PointerType).getBaseType()
    )
    or
    exists(CallExpr ce, string pkg |
      ce.getTarget() instanceof APISchemaBuilder and
      this = ce.getAnArgument().getType().(PointerType).getBaseType() and
      this.hasQualifiedName(pkg, _) and
      not pkg.matches(["k8s.io/%", "sigs.k8s.io/%"])
    )
    or
    exists(DataFlow::Node src |
      isApiObjectLiteral(src, this) and
      SchemeRegistrationFlow::flow(src, _)
    )
  }
}

/**
 * A Go test file. The Go extractor drops these unless the database was built
 * with `extract_tests=true` (default false), so on a default database this class
 * has no members. Any ground truth taken from a repo-wide grep must exclude
 * `*_test.go` before being compared with a QL count.
 */
class GoTestFile extends File {
  GoTestFile() { this.getBaseName().matches("%\\_test.go") }
}

/**
 * A field of `corev1.Secret` holding secret material.
 *
 * Do NOT write this as `f.getDeclaringType().getName() = "Secret"`:
 * `Field.getDeclaringType()` returns the *anonymous* `StructType` underlying the
 * named type, and `Type.getName()` only holds for named types, so that form
 * silently matches nothing.
 */
class K8sSecretDataField extends Field {
  K8sSecretDataField() {
    this.hasQualifiedName("k8s.io/api/core/v1", "Secret", ["Data", "StringData"])
  }
}

/** The Kubernetes `Secret` type, `k8s.io/api/core/v1.Secret`. */
class KubernetesSecret extends Type {
  KubernetesSecret() { this.hasQualifiedName("k8s.io/api/core/v1", "Secret") }
}

/**
 * The `Get` function of `sigs.k8s.io/controller-runtime/pkg/client`, used by a
 * reconciler to fetch an object from the API server.
 */
class K8sGet extends Function {
  K8sGet() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/client" and
    this.getName() = "Get"
  }
}

/**
 * The Kubernetes `SecretKeySelector` type,
 * `k8s.io/api/core/v1.SecretKeySelector`, which names a single key inside a
 * `Secret` and is the usual way a custom resource points at secret material.
 */
class K8sSecretKeySelector extends Type {
  K8sSecretKeySelector() { this.hasQualifiedName("k8s.io/api/core/v1", "SecretKeySelector") }
}

/**
 * Holds if `t` refers to a Kubernetes secret, either by being a
 * `SecretKeySelector` (or a pointer to one) or by transitively containing a
 * field whose type does.
 */
predicate hasSecretRef(Type t) {
  t instanceof K8sSecretKeySelector
  or
  t.(PointerType).getBaseType() instanceof K8sSecretKeySelector
  or
  exists(Field f | f = t.getField(_) and hasSecretRef(f.getType()))
}

/**
 * Gets the type `t` holds one level down: the base type of a pointer, the
 * element type of a slice or array, or the *value* type of a map (never the key
 * type — a `map[string]HeadersSource` carries its payload in the value).
 *
 * `t` is looked through to its underlying type first, so a named container type
 * such as `type NodePools []HumioNodePoolSpec` unwraps as well.
 *
 * This exists because `SliceType`, `ArrayType` and `MapType` do not override
 * `Type.getField`, so a field-following recursion stops dead at any `[]T` or
 * `map[K]V` member unless it unwraps explicitly.
 */
Type unwrap(Type t) {
  exists(Type u | u = t.getUnderlyingType() |
    result = u.(PointerType).getBaseType()
    or
    result = u.(SliceType).getElementType()
    or
    result = u.(ArrayType).getElementType()
    or
    result = u.(MapType).getValueType()
  )
}

/**
 * Holds if `key` is a `Secret` key under which Kubernetes stores *public*
 * certificate material rather than a private key.
 *
 * `tls.crt` (`corev1.TLSCertKey`) is the leaf certificate of a TLS keypair and
 * `ca.crt` is both the CA bundle half of a TLS secret and the
 * `corev1.ServiceAccountRootCAKey` entry of a service-account token secret. All
 * three are published to every client that opens a connection — a CA bundle is
 * literally copied into `CustomResourceDefinition.spec.conversion.webhook` and
 * into webhook configurations by design — so copying them into a custom
 * resource, a ConfigMap or an annotation is not a leak.
 *
 * The private key, `tls.key` (`corev1.TLSPrivateKeyKey`), is deliberately NOT
 * listed: it is the thing this query exists to find.
 *
 * Keys are compared by *constant value*, not by syntax, so a reference to
 * `corev1.TLSCertKey`, to `corev1.ServiceAccountRootCAKey` or to an operator's
 * own `const SecretKeyCACert = "ca.crt"` is recognised as well as a bare string
 * literal.
 */
predicate isPublicCertificateKey(string key) { key = ["tls.crt", "ca.crt"] }

/**
 * A read of an element of a Kubernetes `Secret`'s `Data` or `StringData` map.
 * This is the taint source for secret material.
 *
 * Both ways of getting at an element are matched, because operators use both:
 *
 * - an index expression, `secret.Data["token"]`, which the go library models as
 *   a `DataFlow::ElementReadNode`; and
 * - the value variable of an iteration, `for k, v := range secret.Data`, which
 *   it models as a `DataFlow::RangeElementNode` — a distinct node class that
 *   reads no element and so is *not* covered by `ReadNode.readsElement`.
 *
 * `DataFlow::readsAnElement` is exactly the union of the two, so this class is
 * a `DataFlow::Node` rather than a `DataFlow::ReadNode`: a `RangeElementNode`
 * is not a `ReadNode`, and constraining the type would silently drop the range
 * case again.
 *
 * In both forms the base is required to be the data-flow read of
 * `Secret.Data`/`Secret.StringData` rather than the syntactic expression, so
 * the source survives aliasing of the secret through local variables.
 *
 * The *key* of a range (`for k := range secret.Data`) is a `RangeIndexNode` and
 * is deliberately not matched: a `Secret`'s keys are filename-like names, not
 * secret material.
 *
 * A read whose index is a constant naming public certificate material
 * (`isPublicCertificateKey`) is excluded — see that predicate. This is only
 * possible for the index-expression form: a range over the whole `Data` map
 * names no key, so it stays a source even when the secret happens to be a TLS
 * secret.
 */
class K8sSecretData extends DataFlow::Node {
  K8sSecretData() {
    exists(DataFlow::ReadNode dataRead |
      DataFlow::readsAnElement(this, dataRead) and
      dataRead.readsField(_, "k8s.io/api/core/v1", "Secret", ["Data", "StringData"])
    ) and
    not isPublicCertificateKey(this.(DataFlow::ElementReadNode).getIndex().asExpr().getStringValue())
  }
}

/**
 * Holds if `t` is a Kubernetes custom resource type, or a type reachable from
 * one by following fields and unwrapping pointers, slices, arrays and map
 * values (see `unwrap`).
 *
 * This is the type-level half of `isCustomResourceFieldAccess`: it is what a
 * read or write *base* must be for the accessed field to really belong to a
 * custom resource, rather than merely being the same structural `Field` entity
 * as one that does.
 */
predicate isPartOfCustomResource(Type t) {
  t instanceof CustomResourceType
  or
  exists(Type parent |
    isPartOfCustomResource(parent) and
    t = unwrap*(parent.getField(_).getType())
  )
}

/**
 * Holds if `f` belongs to `metav1.ObjectMeta` or `metav1.TypeMeta`.
 *
 * Every Kubernetes object embeds these, and Go gives structurally identical
 * structs a single `Field` entity, so `ObjectMeta.Name` is *the same* field on a
 * custom resource, a `Deployment`, a `Service` and a `Secret`. Such fields carry
 * no operator-specific meaning and are excluded from both source and sink.
 *
 * `ObjectMeta.Annotations` is an exception handled elsewhere: it is excluded
 * here like every other meta field, and picked up by
 * `SecretMaterializationSink` on its own terms, because an annotation is
 * persisted on whatever object carries it.
 */
predicate isApiMachineryMetaField(Field f) {
  f.hasQualifiedName("k8s.io/apimachinery/pkg/apis/meta/v1", ["ObjectMeta", "TypeMeta"], _)
}

/**
 * Holds if `base` is a value that is part of a Kubernetes custom resource and
 * `f` is one of its own (or promoted, non-`metav1`) fields.
 *
 * Constraining `base` is what stops a wildcarded write/read base from matching
 * any object that happens to share a structural `Field` entity with a custom
 * resource.
 */
predicate isCustomResourceFieldAccess(DataFlow::Node base, Field f) {
  not isApiMachineryMetaField(f) and
  exists(Type owner |
    owner = unwrap*(base.getType()) and
    isPartOfCustomResource(owner) and
    owner.getField(_) = f
  )
}

/**
 * Holds if `f` is the `Type` field of an `encoding/pem.Block`.
 *
 * Its value is the PEM label — the literal `"CERTIFICATE"`, `"RSA PRIVATE KEY"`
 * and so on — never key material, and never anything a CR author controls. It
 * matters because the go taint library's `fieldReadStep` is field-insensitive:
 * once a `*pem.Block` is tainted by `pem.Decode(secret.Data["tls.key"])`, a read
 * of *any* of its fields is tainted, including this label. Any operator that
 * parses certificates out of a `Secret` and then records the label produces an
 * alert that is pure noise.
 *
 * This is not hypothetical: external-secrets' `getKeyFromValue` ends
 * `fmt.Errorf("key type %v is not supported", pemBlock.Type)`, and that error
 * message reaches a CR condition. It is two of the five results this query
 * reported on external-secrets, and both are the label, not the key.
 *
 * The suppression built on this predicate is `PemBlockTypeSanitizer`, a barrier
 * on the *read* of the field. Excluding the field from `isStringishField`
 * instead does nothing at all: the tainted value flows *into* a custom-resource
 * field, so the field under test at the sink is the CR's, and the block's field
 * type is never consulted there.
 */
predicate isPemBlockTypeField(Field f) { f.hasQualifiedName("encoding/pem", "Block", "Type") }

/**
 * The label of a decoded PEM block, suppressed wherever it is read.
 *
 * WARNING — THIS CLASS IS CROSS-CUTTING, AND IT IS THE ONLY ONE IN THIS LIBRARY
 * THAT IS. It extends `TaintTracking::DefaultTaintSanitizer`, which the shared
 * taint library makes a barrier in *every* `TaintTracking::Global` configuration
 * in this pack — `K8sSecretsLeak` and `K8sCustomResourceSqlInjection` alike —
 * without either query naming it in its own `isBarrier`. Reading a query's
 * `isBarrier` therefore does not tell you the whole barrier set; this class is
 * the missing piece. That is deliberate: the PEM label is neither secret
 * material nor attacker-controlled, so it is a sound barrier in both directions.
 * Anyone adding a `TaintTracking::Global` configuration to this pack inherits it
 * silently, and anyone narrowing it changes both existing queries at once.
 *
 * The suppression has to live here, on the *read*, and cannot be expressed as a
 * field-type exclusion at the sink: the false-positive shape is a read of
 * `pem.Block.Type` flowing *into* a custom-resource field, so the field tested
 * at the sink is the CR's own, and the block's field never appears there. An
 * exclusion in `isStringishField` is provably inert — deleting one changes no
 * result on the test suite or the measured corpus.
 */
private class PemBlockTypeSanitizer extends TaintTracking::DefaultTaintSanitizer {
  PemBlockTypeSanitizer() {
    exists(Field f | isPemBlockTypeField(f) | this.(DataFlow::FieldReadNode).readsField(_, f))
  }
}

/**
 * Holds if `t` is a string-ish type: `string`, a *named* type whose underlying
 * type is `string` (`type HumioClusterState string`), or a byte slice.
 *
 * Testing `t instanceof StringType` is not enough: `StringType` is a
 * `BasicType`, whereas `type Foo string` is a `DefinedType`, so the direct test
 * silently misses the named string types Kubernetes CRDs use heavily.
 * `t.getName() = "string"` is exactly equivalent and equally wrong.
 */
predicate isStringishType(Type t) {
  t.getUnderlyingType() instanceof StringType
  or
  t.getUnderlyingType() instanceof ByteSliceType
}

/**
 * Holds if `f` has a string-ish type (see `isStringishType`).
 *
 * This deliberately carries no exclusion for `encoding/pem.Block.Type`. The PEM
 * label is suppressed by `PemBlockTypeSanitizer`, a barrier on the *read*; an
 * exclusion here would be inert, because the field tested at the sink is the
 * custom resource's, not the block's. See `isPemBlockTypeField`.
 */
predicate isStringishField(Field f) { isStringishType(f.getType()) }

/**
 * Holds if `f` is a container field whose *elements* are string-ish:
 * `[]string`, `map[string]string`, `[][]byte`, `map[string]TokenString`, and so
 * on, following `unwrap` (pointers, slices, arrays and map values).
 *
 * This is what makes `cr.Spec.List = append(cr.Spec.List, secretValue)` a sink.
 * The written node there is the *result of `append`*, whose type is the slice,
 * not the element, so `isStringishField` alone never matches it and the write is
 * invisible. A `[]byte` field is already string-ish in its own right and is
 * matched by `isStringishField`, not here (`unwrap` of `[]byte` is `byte`).
 */
predicate isStringishContainerField(Field f) { isStringishType(unwrap+(f.getType())) }

/**
 * Holds if `t` is the `Status` type of a registered custom resource: a type
 * reachable from a `CustomResourceType` whose name ends in `Status`.
 *
 * This is an approximation, and the reason for it is that the CRD YAML is not in
 * the database. What actually makes a status field non-attacker-controlled is
 * `subresources: {status: {}}` in the CRD manifest: with it, the API server
 * strips any user-supplied `status` on create and update, so only the operator
 * ever writes there. The manifest is not extracted, so the type name stands in
 * for it.
 *
 * Limits of the approximation, all of them deliberate:
 *
 * - A CR whose CRD does *not* declare the status subresource has a genuinely
 *   user-writable status, and this predicate wrongly excludes it. That is the
 *   minority case; kubebuilder emits `+kubebuilder:subresource:status` for
 *   essentially every operator CRD.
 * - It keys on the *name*, so a status struct called something else
 *   (`FooState`) is not excluded, and a spec struct that happens to end in
 *   `Status` is.
 * - Only the type directly declaring the field is tested, so a field of a
 *   sub-struct nested under the status (`cr.Status.Conditions[0].Message`) is
 *   still treated as attacker-controlled.
 */
predicate isCustomResourceStatusType(Type t) {
  isPartOfCustomResource(t) and
  t.getName().matches("%Status")
}

/**
 * Holds if every custom-resource type that could witness the access of `f` on
 * `base` is a status type (see `isCustomResourceStatusType`).
 *
 * `forex` rather than `exists` because Go gives structurally identical structs a
 * single `Field` entity: if the same field is reachable both under a status and
 * under a spec, the spec reading is the one that decides, and the read stays a
 * source.
 */
predicate isCustomResourceStatusFieldAccess(DataFlow::Node base, Field f) {
  forex(Type owner |
    owner = unwrap*(base.getType()) and
    isPartOfCustomResource(owner) and
    owner.getField(_) = f
  |
    isCustomResourceStatusType(owner)
  )
}

/**
 * A read of a string-typed field of a Kubernetes custom resource, used as a
 * taint source for values an operator's user controls through a CR manifest.
 *
 * Reads of fields under the CR's `Status` are excluded: the API server strips
 * user-supplied status whenever the CRD declares the status subresource, so
 * those values come from the operator itself, not from the manifest author. See
 * `isCustomResourceStatusType` for what that approximation does and does not
 * cover.
 */
class CustomResourceValueSource extends DataFlow::ReadNode {
  CustomResourceValueSource() {
    exists(Field f, DataFlow::Node base |
      this.readsField(base, f) and
      isCustomResourceFieldAccess(base, f) and
      isStringishField(f) and
      not isCustomResourceStatusFieldAccess(base, f)
    )
  }
}

/**
 * Holds if `container` is a map, slice or array that belongs to a custom
 * resource and whose elements are string-ish — the thing being indexed in
 * `cr.Spec.Fields[key] = secretValue`.
 *
 * The container is identified by the *field read* that produced it, so the CR
 * base constraint of `isCustomResourceFieldAccess` still applies; a bare
 * `map[string]string` local, which shares its `Type` entity with every other
 * `map[string]string` in the program, is not enough. `DataFlow::localFlow` (which
 * is reflexive) lets the write happen through an alias:
 * `m := cr.Spec.Fields; m[key] = secretValue`.
 */
predicate isCustomResourceStringishContainer(DataFlow::Node container) {
  exists(DataFlow::ReadNode fieldRead, DataFlow::Node base, Field f |
    fieldRead.readsField(base, f) and
    isCustomResourceFieldAccess(base, f) and
    isStringishContainerField(f) and
    not f instanceof K8sSecretDataField and
    DataFlow::localFlow(fieldRead, container)
  )
}

/**
 * A value written into a string-typed field of a Kubernetes custom resource, or
 * into a string-typed element of one of its maps, slices or arrays.
 *
 * Three shapes are matched, and all three occur in real operators:
 *
 * - a field write, `cr.Spec.Token = secretValue`;
 * - a field write whose value is a *container* of strings, which is what
 *   `cr.Spec.List = append(cr.Spec.List, secretValue)` compiles to — the written
 *   node is the result of `append`, typed `[]string`, so `isStringishField` never
 *   matches it (see `isStringishContainerField`); and
 * - an element write, `cr.Spec.Fields[key] = secretValue`, which produces no
 *   field write at all and so was previously invisible.
 *
 * The element case uses `writesElementPreUpdate` rather than `writesElement`
 * because the pre-update base is the field read of the container itself, which is
 * what `isCustomResourceStringishContainer` has to match; `writesElement` hands
 * back a `PostUpdateNode` instead.
 *
 * `Secret.Data` and `Secret.StringData` are excluded as destinations. A
 * `corev1.Secret` is reachable from the CR type graph of real operators
 * (kubeblocks embeds one), `Secret.Data` is a `map[string][]byte` and therefore a
 * string-ish container, and operators copy secrets into other secrets constantly
 * — `dst.Data[key] = src.Data[key]`, `builder.get().Data = data`. Moving secret
 * material into a `Secret` is not a leak; a `Secret` is where it belongs. Without
 * this, the element-write case alone contributes twelve results on kubeblocks,
 * every one of them a secret-to-secret copy.
 */
class CustomResourceFieldSink extends DataFlow::Node {
  CustomResourceFieldSink() {
    exists(Field f, Write w, DataFlow::Node base |
      w.writesField(base, f, this) and
      isCustomResourceFieldAccess(base, f) and
      not f instanceof K8sSecretDataField and
      (isStringishField(f) or isStringishContainerField(f))
    )
    or
    exists(Write w, DataFlow::Node container |
      w.writesElementPreUpdate(container, _, this) and
      isCustomResourceStringishContainer(container)
    )
  }
}

/**
 * Holds if `f` is a field into which writing secret material materialises that
 * secret somewhere the operator persists it, whatever object it belongs to.
 *
 * Unlike the custom-resource sinks, these are pinned by qualified name alone and
 * carry no base constraint, because the field identity *is* the persistence
 * argument:
 *
 * - `corev1.EnvVar.Value` — a literal environment-variable value. `EnvVar` exists
 *   in the Kubernetes API only inside a container spec, so an `EnvVar` the
 *   operator builds ends up in a PodSpec, in the pod's `/proc/<pid>/environ`, and
 *   readable by anyone with `get pod`. This is the shape of the one real
 *   `EnvVar.Value` finding in the 45-operator hunt (kserve `BuildSecretEnvs`).
 * - `corev1.ConfigMap.Data` / `BinaryData` — a ConfigMap is the explicitly
 *   *non*-secret half of the API. Anything written here is readable by every
 *   subject with `get configmap`, which is a far wider set than `get secret`.
 * - `metav1.ObjectMeta.Annotations` — annotations are persisted on the object and
 *   show up in `kubectl get -o yaml`, in `last-applied-configuration`, and in
 *   every audit log entry for the object.
 */
predicate isSecretMaterializationField(Field f) {
  f.hasQualifiedName("k8s.io/api/core/v1", "EnvVar", "Value")
  or
  f.hasQualifiedName("k8s.io/api/core/v1", "ConfigMap", ["Data", "BinaryData"])
  or
  f.hasQualifiedName("k8s.io/apimachinery/pkg/apis/meta/v1", "ObjectMeta", "Annotations")
}

/**
 * A value written into a destination that materialises it as persisted,
 * non-secret data: an environment variable value, a ConfigMap entry or an
 * annotation. See `isSecretMaterializationField` for why each of those is a leak
 * in its own right.
 *
 * This is a sibling of `CustomResourceFieldSink`, not a case of it, and it
 * deliberately does not inherit the custom-resource base constraint: none of
 * these destinations is a custom-resource field, and requiring one would have
 * meant either a class whose name no longer described its contents or a base
 * constraint that discarded exactly the findings this class exists for. The two
 * whole-map shapes are both matched — `cm.Data = map[string]string{...}` (a field
 * write, whose value carries taint from its own element initialisers) and
 * `cm.Data[key] = value` (an element write into the field read).
 *
 * Not matched, and worth knowing: `obj.SetAnnotations(m)` and the other
 * accessor methods of `metav1.Object`, which reach the same field through an
 * interface call rather than a field write.
 */
class SecretMaterializationSink extends DataFlow::Node {
  SecretMaterializationSink() {
    exists(Write w, Field f |
      isSecretMaterializationField(f) and
      w.writesField(_, f, this)
    )
    or
    exists(Write w, DataFlow::ReadNode container, Field f |
      isSecretMaterializationField(f) and
      container.readsField(_, f) and
      w.writesElementPreUpdate(container, _, this)
    )
  }
}

/**
 * A place where secret material must not land: a custom-resource field
 * (`CustomResourceFieldSink`) or a destination that materialises the value as
 * persisted, non-secret data (`SecretMaterializationSink`).
 */
class SecretLeakSink extends DataFlow::Node {
  SecretLeakSink() {
    this instanceof CustomResourceFieldSink
    or
    this instanceof SecretMaterializationSink
  }
}
