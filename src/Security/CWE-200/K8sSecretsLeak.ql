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

/**
 * A taint-tracking configuration for values read out of a Kubernetes `Secret`
 * flowing into a string field of a registered custom resource.
 */
module SecretToCrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof K8sSecretData }

  predicate isSink(DataFlow::Node n) { n instanceof CustomResourceSink }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module SecretToCrFlow = TaintTracking::Global<SecretToCrConfig>;

import SecretToCrFlow::PathGraph

from SecretToCrFlow::PathNode source, SecretToCrFlow::PathNode sink
where SecretToCrFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Secret value is leaked in Custom Resource"
