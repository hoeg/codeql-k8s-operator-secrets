/**
 * @name Exposing secret values in k8s custom resources
 * @description A secret value is assigned to a variable of a kubernetes custom resource
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @precision medium
 * @id go/k8s-secrets-leak
 * @tags security
 *       external/cwe/cwe-200
 */

import go
import K8sOperators
import Barriers

/**
 * A taint-tracking configuration for values read out of a Kubernetes `Secret`
 * flowing into a string field of a registered custom resource.
 */
module SecretToCrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof K8sSecretData }

  predicate isSink(DataFlow::Node n) { n instanceof SecretLeakSink }

  /**
   * Two barriers, both defined in `Barriers.qll`:
   *
   * - `getAGuardedEnvVarValueRead()` — a *read* of `EnvVar.Value` made under an
   *   equality check on the corresponding `EnvVar.Name`. Container environment is
   *   a flat `[]corev1.EnvVar`, and the data-flow library does not correlate the
   *   `Name` and `Value` of a slice element, so an operator that appends one
   *   secret-bearing `EnvVar` taints the `Value` of every element any later loop
   *   reads. The name check re-establishes that correlation.
   *
   * - `getATypeVerbFormattedArgument()` — an argument of a `fmt` formatting call
   *   whose verb is `%T`. `%T` prints the argument's Go type name and never its
   *   contents, so it is unconditionally sound as a barrier.
   *
   * `%w` is deliberately *not* a barrier here, even though `Barriers.qll` also
   * offers `getAFormatVerbBarrierArgument()`, which covers both verbs. `%w` only
   * records the argument as a wrapped error; `Error()` on the wrapper
   * concatenates the wrapped error's message, so a secret already inside that
   * message stays readable through the wrapper and `%w` is not a true sanitizer.
   * It cost recall on real code: in external-secrets a resolved secret is passed
   * to `fmt.Errorf` as the *format string*
   * (`providers/v1/previder/provider.go:56`), and the resulting error is wrapped
   * through `%w` into a `PushSecret` status `Message` — a genuine flow from
   * `runtime/esutils/resolvers/secret_ref.go:68` that the `%w` disjunct removed.
   * On the measured corpus (kserve, cert-manager, humio-operator,
   * postgres-operator, external-secrets) no `%T` node appears on any path of this
   * query, so dropping `%w` here is pure recall with no measured precision loss.
   * The SQL-injection query is a separate trade-off and is unaffected: it keeps
   * `getAFormatVerbBarrierArgument()`, where `%T` removes a false positive that
   * its test pins.
   *
   * Note the interaction between the first barrier and `SecretMaterializationSink`,
   * which makes a *write* into `EnvVar.Value` a sink: the two touch the same field
   * but never the same node. The barrier only ever holds of a `FieldReadNode`, the
   * sink only of the value written into a field, so a guarded `envVar.Value` read
   * that is later appended to another container's `Env` is cut, while secret
   * material written straight into a freshly built `EnvVar{Value: ...}` — kserve's
   * `BuildSecretEnvs`, the one real `EnvVar.Value` finding in the 45-operator hunt
   * — is untouched, because no `EnvVar.Value` read occurs on its path at all.
   */
  predicate isBarrier(DataFlow::Node n) {
    n = getAGuardedEnvVarValueRead()
    or
    n = getATypeVerbFormattedArgument()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module SecretToCrFlow = TaintTracking::Global<SecretToCrConfig>;

import SecretToCrFlow::PathGraph

from SecretToCrFlow::PathNode source, SecretToCrFlow::PathNode sink
where SecretToCrFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret value is leaked in Custom Resource"
