/*
@kind path-problem
*/

import go
import DataFlow::PathGraph

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

private class K8sSecretKeySelector extends Type {
  K8sSecretKeySelector() {
        this.getPackage().getPath() = "k8s.io/api/core/v1" 
    and this.getName() = "SecretKeySelector"
  }
}

predicate hasSecretRef(Type t) {
  t instanceof K8sSecretKeySelector
  or t.(PointerType).getBaseType() instanceof K8sSecretKeySelector
  or exists(Field f | 
    f = t.getField(_)
    and hasSecretRef(f.getType())
  )
}

predicate isPartOfCr(Assignment a) {
  exists(SelectorExpr s |
    s = a.getAnLhs() 
    and s.getSelector().getType() instanceof CustomResourceType 
    and hasSecretRef(s.getSelector().getType())
  )
}

from DataFlow::Node n, Assignment a
where n.asExpr() = a.getAnLhs().getAChildExpr()
select a