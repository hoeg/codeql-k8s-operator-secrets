/**
 * @name Database query built from Kubernetes custom resource fields
 * @description Building a database query from string fields of a Kubernetes custom resource lets
 *              anyone who can create or edit that custom resource inject arbitrary query syntax
 *              into the operator's database queries.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id go/k8s-cr-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import semmle.go.security.SqlInjectionCustomizations
import K8sOperators

/**
 * A taint-tracking configuration for data flowing from a string field of a
 * Kubernetes custom resource into a SQL or NoSQL query.
 */
module CrToSqlConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof CustomResourceValueSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    NoSql::isAdditionalMongoTaintStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CrToSqlFlow = TaintTracking::Global<CrToSqlConfig>;

import CrToSqlFlow::PathGraph

from CrToSqlFlow::PathNode source, CrToSqlFlow::PathNode sink
where CrToSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data from custom resource in SQL query"
