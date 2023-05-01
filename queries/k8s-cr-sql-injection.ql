/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

 import go
 import semmle.go.security.SqlInjectionCustomizations
 import DataFlow::PathGraph


 private class SchemaBuilder extends Function  {
    SchemaBuilder() {
      this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
      and 
      this.getName() = "Register"
    }
  }

 private class CustomResourceType extends Type {
    CustomResourceType() {
      exists(CallExpr ce, Function f, Expr e, PointerType pt, TypeSpec ts | 
            f = ce.getTarget()
        and f instanceof SchemaBuilder
        and e = ce.getAnArgument()
        and pt = e.getType()
        and this = pt.getBaseType()
        and ts.getName() = this.getName()
      )
    }
  }

  predicate isNestedFieldInCustomResource(Type customResource, Field field) {
    exists(Type nestedType, Field parentField |
      (nestedType = parentField.getType().(PointerType).getBaseType() 
      or nestedType = parentField.getType()) and
      customResource.getField(_) = parentField and
      isNestedFieldInCustomResource(nestedType, field)
    ) or
    customResource.getField(_) = field
  }

class CustomResourceValueSource extends DataFlow::ReadNode {
  CustomResourceValueSource() {
    exists(Field f, CustomResourceType cr |
      isNestedFieldInCustomResource(cr, f) and
      this.readsField(_, f) and f.getType() instanceof StringType
    )
  }
}

class K8sCustomResourceSqlInjectionConfiguration extends TaintTracking::Configuration {
  K8sCustomResourceSqlInjectionConfiguration() { this = "K8sCustomResourceSqlInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof CustomResourceValueSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
    NoSql::isAdditionalMongoTaintStep(pred, succ)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node) or
    node instanceof SqlInjection::Sanitizer
  }

  deprecated override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof SqlInjection::SanitizerGuard
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, K8sCustomResourceSqlInjectionConfiguration cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Data from custom resource in SQL query"