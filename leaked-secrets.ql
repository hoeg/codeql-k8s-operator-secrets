import go
import DataFlow::PathGraph

private class KubernetesSecret extends Type {
  KubernetesSecret() {
        this.getPackage().getPath() = "k8s.io/api/core/v1" 
    and this.getName() = "Secret"
  }
}

private class K8sGet extends Function {
  K8sGet() {
        this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/client"
    and this.getName() = "Get"
  }
}

private class Source extends DataFlow::Node {
  Source() {
    exists(CallExpr ce, Expr e, PointerType pt, Function f | 
      f = ce.getTarget()
      and f instanceof K8sGet
      and e = ce.getAnArgument()
      and pt = e.getType()
      and pt.getBaseType() instanceof KubernetesSecret
      and this.asExpr() = e)
  }
}

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

private class Sink extends DataFlow::Node {
  Sink() {
    exists(DataFlow::AssignStmt ass, TypeDecl td, TypeSpec ts, CustomResourceType crt, StructTypeExpr ste, Field f, Write w, StructType st | 
      td.getASpec() = ts
      and ts.getName() = crt.getName()
      and ste = ts.getAChildExpr()
      and ste.getType() = st
      and f = st.getField(_) 
      and w = f.getAWrite()
      and ass.getRhs() = w.getRhs().asExpr()
      and this.asExpr() = ass.getLhs())
  }
}

class Configuration extends TaintTracking::Configuration {
  Configuration() {this = "LeakedSecrets"}

  override predicate isSource(DataFlow::Node source) {source instanceof Source}

  override predicate isSink(DataFlow::Node sink) {sink instanceof Sink}
}

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select source, sink