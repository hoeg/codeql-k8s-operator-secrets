/**
 * Exploration: data-flow nodes for the `*corev1.Secret` argument passed to
 * `client.Get`, the candidate taint source for secret material.
 */

import go
import K8sOperators

from DataFlow::CallNode call, CallExpr ce, Expr e, PointerType pt, Function f, DataFlow::Node secret
where
  call.getCall() = ce and
  f = ce.getTarget() and
  f instanceof K8sGet and
  e = ce.getAnArgument() and
  e = secret.asExpr() and
  pt = e.getType() and
  pt.getBaseType() instanceof KubernetesSecret
select secret, f
