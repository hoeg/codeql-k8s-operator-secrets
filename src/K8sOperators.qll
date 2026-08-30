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
 */
class K8sSecretData extends DataFlow::Node {
  K8sSecretData() {
    exists(DataFlow::ReadNode dataRead |
      DataFlow::readsAnElement(this, dataRead) and
      dataRead.readsField(_, "k8s.io/api/core/v1", "Secret", ["Data", "StringData"])
    )
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
 * Holds if `f` has a string-ish type: a `string`, a *named* type whose
 * underlying type is `string` (`type HumioClusterState string`), or a byte
 * slice.
 *
 * Testing `f.getType() instanceof StringType` is not enough: `StringType` is a
 * `BasicType`, whereas `type Foo string` is a `DefinedType`, so the direct test
 * silently misses the named string types Kubernetes CRDs use heavily.
 * `f.getType().getName() = "string"` is exactly equivalent and equally wrong.
 */
predicate isStringishField(Field f) {
  f.getType().getUnderlyingType() instanceof StringType
  or
  f.getType().getUnderlyingType() instanceof ByteSliceType
}

/**
 * A read of a string-typed field of a Kubernetes custom resource, used as a
 * taint source for values an operator's user controls through a CR manifest.
 */
class CustomResourceValueSource extends DataFlow::ReadNode {
  CustomResourceValueSource() {
    exists(Field f, DataFlow::Node base |
      this.readsField(base, f) and
      isCustomResourceFieldAccess(base, f) and
      isStringishField(f)
    )
  }
}

/**
 * A value written to a string-typed field of a Kubernetes custom resource, used
 * as a taint sink for data that must not be persisted into a CR.
 */
class CustomResourceSink extends DataFlow::Node {
  CustomResourceSink() {
    exists(Field f, Write w, DataFlow::Node base |
      w.writesField(base, f, this) and
      isCustomResourceFieldAccess(base, f) and
      isStringishField(f)
    )
  }
}
