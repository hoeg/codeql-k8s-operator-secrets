/**
 * Exploration: arguments to `client.Get` that are pointers to a Kubernetes
 * `Secret`, i.e. the object the reconciler fills in with secret material.
 *
 * The argument is only the Secret itself; what is actually used is the data
 * inside it, which is what `K8sSecretData` in the library matches.
 */

import go
import K8sOperators

from CallExpr ce, Expr e, PointerType pt, Function f
where
  f = ce.getTarget() and
  f instanceof K8sGet and
  e = ce.getAnArgument() and
  pt = e.getType() and
  pt.getBaseType() instanceof KubernetesSecret
select e
