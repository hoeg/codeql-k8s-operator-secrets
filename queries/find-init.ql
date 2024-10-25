import go

private class SchemaBuilder extends Function  {
  SchemaBuilder() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
    and 
    this.getName() = "Register"
  }
}

private class APISchemaBuilder extends Function {
  APISchemaBuilder() {
    this.getName() = "AddKnownTypes"
    and 
    this.getPackage().getPath() = "k8s.io/apimachinery/pkg/runtime"
  }
} 
private class SchemaBuilder extends Function  {
  SchemaBuilder() {
    this.getName() = "Register"
    and exists(CallExpr ce, PointerType pt | ce.getTarget().getType() = pt 
    and pt.getUnderlyingType().getName() = "SchemaBuilder")
  }
}


from CallExpr ce, Function f, Expr e, PointerType pt
where f = ce.getTarget()
  and (f instanceof APISchemaBuilder or f instanceof SchemaBuilder)
  and e = ce.getAnArgument()
  and pt = e.getType()
select ce.getLocation(), pt.getBaseType()
