import go

private class SchemaBuilder extends Function  {
  SchemaBuilder() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
    and 
    this.getName() = "Register"
  }
}

private class CustomResourceType extends Type {
  CustomResourceType() {
    exists(CallExpr ce, Function f, Expr e, PointerType pt | 
          f = ce.getTarget()
      and f instanceof SchemaBuilder
      and e = ce.getAnArgument()
      and pt = e.getType()
      and pt.getBaseType().getName() = this.getName()
    )
  }
}

from Field fi, Write write, Type t, Expr oute, StructTypeExpr str, 
      CallExpr ce, Function f, Expr e, PointerType pt
where f = ce.getTarget()
and f instanceof SchemaBuilder
and e = ce.getAnArgument()
and pt = e.getType()
and t = pt.getBaseType()
and oute.getType() = t
and t instanceof NamedType
//and pt.getBaseType() = stt
//and pt.getBaseType().getName() = ste.getType().getName()
select oute.getLocation()


/*
//Writes to Url field
from Field f, Write write, StructType stt, StructTypeExpr ste
where 
  stt.hasField("Url", _)
  and ste.getType() = stt
  and stt.getField("Url") = f
  and write = f.getAWrite()
select write.getRhs()
*/