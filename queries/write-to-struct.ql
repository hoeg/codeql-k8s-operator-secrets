import go

//first
private class SchemaBuilder extends Function  {
  SchemaBuilder() {
    this.getPackage().getPath() = "sigs.k8s.io/controller-runtime/pkg/scheme"
    and 
    this.getName() = "Register"
  }
}

//explorative using select and print AST
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
/*
from CustomResourceType crt, TypeSpec ts
where crt.getName() = ts.getName()
select ts.getLocation(), "YES!"
*/

from TypeDecl td, TypeSpec ts, CustomResourceType crt, StructTypeExpr ste,
  Field f, Write w, StructType st
where
  td.getASpec() = ts
  and ts.getName() = crt.getName()
  and ste = ts.getAChildExpr()
  and ste.getType() = st
  and f = st.getField(_) 
  and w = f.getAWrite()
select w.getLhs(), w.getRhs()


//lifted example from the web to help with finding writes
//Writes to Url field
/*
from Field f, Write write, StructType stt, StructTypeExpr ste
where 
  stt.hasField("Url", _)
  and ste.getType() = stt
  and stt.getField("Url") = f
  and write = f.getAWrite()
select write.getRhs()
*/