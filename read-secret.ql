import go

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


//first returned ce.getLocation() but it dawned on me that I need the secret.
//it should be the argument that is the sink!!

//alas the argument is just the secret. What is actually set used is the data inside the secret! We need to find that!
from CallExpr ce, Expr e, PointerType pt, Function f, Read r
where f = ce.getTarget()
  and f instanceof K8sGet
  and e = ce.getAnArgument()
  and pt = e.getType()
  and pt.getBaseType() instanceof KubernetesSecret
select e