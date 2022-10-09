import go


/*
Having trouble figuring out the source. It seems to be the assignment of the value inside the
secert so lets try to figure out where it is done.
*/

private class KubernetesSecret extends Type {
  KubernetesSecret() {
        this.getPackage().getPath() = "k8s.io/api/core/v1" 
    and this.getName() = "Secret"
  }
}

predicate readsSecretValue(IndexExpr ie) {
  exists(SelectorExpr se, Ident i, PointerType pt, Type t, Ident i2| 
    ie.getAChild() = se
    and se.getAChild() = i
    and i.getType() = pt
    and t = pt.getBaseType()
    and t instanceof KubernetesSecret
    and se.getAChild() = i2
    and i2.getName() = "Data"
  )
}

from IndexExpr ie
where readsSecretValue(ie)
select ie.getLocation()