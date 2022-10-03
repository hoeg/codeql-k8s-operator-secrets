import go

private class SchemaBuilder extends Function  {
  SchemaBuilder() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
    and 
    this.getName() = "Register"
  }
}

from CallExpr ce, Function f, Expr e, PointerType pt
where f = ce.getTarget()
  and f instanceof SchemaBuilder
  and e = ce.getAnArgument()
  and pt = e.getType()
select ce.getLocation(), pt.getBaseType()