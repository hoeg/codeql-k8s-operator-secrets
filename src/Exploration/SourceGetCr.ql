/**
 * Exploration: calls to `Get` that fetch a custom resource whose type
 * transitively contains a `SecretKeySelector`, i.e. a CR that points at secret
 * material.
 */

import go
import K8sOperators

from DataFlow::CallNode cn, DataFlow::Node arg, Type t
where
  arg = cn.getAnArgument() and
  arg.asExpr().getType().(PointerType).getBaseType() = t and
  t instanceof CustomResourceType and
  hasSecretRef(t) and
  cn.getCalleeName() = "Get"
select cn, t.getName()
