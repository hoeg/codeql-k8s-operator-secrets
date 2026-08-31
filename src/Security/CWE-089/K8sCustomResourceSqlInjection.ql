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
import Barriers

/**
 * Holds if `node` is the result of a `+` whose operands are strings.
 *
 * `StringOps::Concatenation` is deliberately not used: `codeql/go-all` 7.3.0
 * ships no `StringOps::Concatenation::Range` subclass, so that class is empty
 * and a condition written in terms of it would silently match nothing. The
 * underlying type is tested rather than the type itself so that a concatenation
 * whose result is a named string type (`type TableName string`) still counts.
 *
 * `q += part` is covered too: the Go IR desugars a compound assignment into the
 * same binary-operation instruction as `q = q + part`.
 */
predicate stringConcatenation(DataFlow::Node node) {
  exists(DataFlow::BinaryOperationNode plus |
    node = plus and
    plus.getOperator() = "+" and
    plus.getType().getUnderlyingType() instanceof StringType
  )
}

/**
 * Holds if `node` is the string (or byte-slice) result of a `fmt` call that
 * interpolates its arguments into a template.
 *
 * Only the `Sprint` and `Append` families are listed. `Errorf` is excluded
 * because its result is an `error` rather than query text, and `Printf`/
 * `Fprintf` write to a stream instead of producing a value a driver could be
 * handed.
 */
predicate formatCallResult(DataFlow::Node node) {
  exists(Function f |
    f.hasQualifiedName("fmt", ["Sprint", "Sprintf", "Sprintln", "Append", "Appendf", "Appendln"]) and
    node = f.getACall().getResult()
  )
}

/**
 * Holds if `node` holds text that was *built*, rather than merely carried: the
 * result of a string concatenation or of a `fmt` interpolation.
 *
 * This is the property that separates injection from parameter passing. A value
 * concatenated or interpolated into a statement is read back by the database's
 * parser as syntax, so a `'` or `;` in it changes the statement. A value handed
 * to the driver as a whole operand -- a bind parameter, a BSON document value --
 * travels out of band and is re-read as a single scalar whatever it contains.
 */
predicate constructedQueryText(DataFlow::Node node) {
  stringConcatenation(node)
  or
  formatCallResult(node)
}

/** Holds if `t` is a BSON document or document-entry type of the MongoDB driver. */
predicate bsonDocumentType(Type t) {
  t.hasQualifiedName(package("go.mongodb.org/mongo-driver", "bson/primitive"), ["M", "D", "E"])
  or
  t.hasQualifiedName(package("go.mongodb.org/mongo-driver", "bson"), ["M", "D", "E"])
}

/**
 * Holds if `node` sits in the *value* position of a BSON document:
 * `bson.M{"name": node}` and `primitive.M{"name": node}` via the map-literal
 * disjunct, and the `Value` field of a `primitive.E` -- the element type of a
 * `bson.D` -- via the field-write disjunct. The field-write disjunct covers both
 * ways that field is set, because the Go extractor models a struct literal's
 * field initialisation as a `Write` just as it does an assignment: it matches
 * `bson.D{{Key: "name", Value: node}}` and `e.Value = node` alike.
 *
 * A Go `string` in that position always marshals to a BSON string. `$ne`,
 * `$in`, `$where` and nested documents are operators only in the *key* position
 * and in documents the driver itself builds, so a value there is inert however
 * it is spelled. This is the `bson.M{"n": bson.M{"$in": hosts}}` shape in
 * percona-server-mongodb-operator that the query used to report.
 *
 * Known miss: `bson.M{"$where": "this.n == '" + crField + "'"}` puts injectable
 * *JavaScript* in a value position, and this predicate hides it. `$where` is
 * disabled by default on modern MongoDB deployments; the FP cost of keeping
 * value positions live was judged higher.
 *
 * Also not covered: `m["k"] = node` on a `bson.M` variable. No operator in the
 * corpus builds a document that way.
 *
 * An earlier revision spelled the literal form out a second time, as a
 * composite-literal value whose key is the identifier `Value`. Mutation testing
 * showed that disjunct was dead: deleting it left both BSON literal fixtures
 * quiet and every corpus result unchanged, because `Write.writesField` already
 * matched the same nodes. It was deleted rather than kept as untested weight.
 */
predicate bsonDocumentValue(DataFlow::Node node) {
  exists(MapLit lit |
    node.asExpr() = lit.getValue(_) and
    bsonDocumentType(lit.getType())
  )
  or
  exists(Write w, Field f |
    w.writesField(_, f, node) and
    f.hasQualifiedName(package("go.mongodb.org/mongo-driver", "bson/primitive"), "E", "Value")
  )
}

/**
 * Holds if `node` is passed to a database call at an argument position after the
 * call's query string, that is, as a `?` or `$n` bind parameter.
 *
 * The driver sends bind parameters separately from the statement text, so their
 * contents are never parsed as query syntax.
 *
 * This is defence in depth and nothing more: `codeql/go-all` models only the
 * statement argument of `Query`/`Exec`/`QueryContext`/`ExecContext` as a sink,
 * so a bind parameter is not a sink to begin with, and no path in this query
 * ends on one. Removing this predicate changes no result in the test suite and
 * none on the 49-database corpus. It is kept so that a driver model which does
 * mark the variadic argument -- or a future `QueryString` at an index other
 * than the statement's -- cannot silently turn parameter passing into a report.
 */
predicate bindParameterArgument(DataFlow::Node node) {
  exists(CallExpr call, int queryIndex, int i |
    DataFlow::exprNode(call.getArgument(queryIndex)) instanceof SQL::QueryString and
    i > queryIndex and
    node = DataFlow::exprNode(call.getArgument(i))
  )
}

private newtype TQueryTextState =
  TRawValue() or
  TConstructedText()

/**
 * Whether the custom-resource value tracked along a path has been built into
 * query text yet.
 *
 * A path starts in `TRawValue` and moves to `TConstructedText` at the first
 * concatenation or `fmt` interpolation it passes through; only
 * `TConstructedText` reaches a sink. Tracking this as flow state rather than
 * inspecting the sink locally is what keeps the construction and the query call
 * from having to sit in the same function: clickhouse-operator, schemahero and
 * percona-xtradb-cluster-operator all build the statement in one function and
 * execute it in a generic `Exec(ctx, sql)` helper, and a sink-local test drops
 * every one of those.
 */
class QueryTextState extends TQueryTextState {
  /** Gets a textual representation of this state. */
  string toString() {
    this = TRawValue() and result = "raw value"
    or
    this = TConstructedText() and result = "constructed query text"
  }
}

/**
 * A taint-tracking configuration for data flowing from a string field of a
 * Kubernetes custom resource into query text that the operator builds and
 * executes.
 */
module CrToSqlConfig implements DataFlow::StateConfigSig {
  final class FlowState = QueryTextState;

  predicate isSource(DataFlow::Node source, FlowState state) {
    source instanceof CustomResourceValueSource and state = TRawValue()
  }

  predicate isSink(DataFlow::Node sink, FlowState state) {
    sink instanceof SqlInjection::Sink and
    state = TConstructedText() and
    not bindParameterArgument(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof SqlInjection::Sanitizer
    or
    node = getAFormatVerbBarrierArgument()
    or
    bsonDocumentValue(node)
    or
    bindParameterArgument(node)
  }

  predicate isAdditionalFlowStep(
    DataFlow::Node node1, FlowState state1, DataFlow::Node node2, FlowState state2
  ) {
    node1 = node2 and
    state1 = TRawValue() and
    state2 = TConstructedText() and
    constructedQueryText(node1)
  }

  predicate isAdditionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    NoSql::isAdditionalMongoTaintStep(pred, succ)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module CrToSqlFlow = TaintTracking::GlobalWithState<CrToSqlConfig>;

import CrToSqlFlow::PathGraph

from CrToSqlFlow::PathNode source, CrToSqlFlow::PathNode sink
where CrToSqlFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Data from custom resource in SQL query"
