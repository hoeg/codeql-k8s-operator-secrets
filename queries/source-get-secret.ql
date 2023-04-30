/*
@kind path-problem
*/

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
  
  from DataFlow::CallNode call, CallExpr ce, Expr e, PointerType pt, Function f, DataFlow::Node secret
  where call.getCall() = ce
    and f = ce.getTarget()
    and f instanceof K8sGet
    and e = ce.getAnArgument()
    and e = secret.asExpr()
    and pt = e.getType()
    and pt.getBaseType() instanceof KubernetesSecret
  select secret, f