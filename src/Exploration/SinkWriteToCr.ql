/**
 * Exploration: assignments whose left-hand side selects a field of a custom
 * resource type that transitively contains a `SecretKeySelector`.
 */

import go
import K8sOperators

predicate isPartOfCr(Assignment a) {
  exists(SelectorExpr s |
    s = a.getAnLhs() and
    s.getSelector().getType() instanceof CustomResourceType and
    hasSecretRef(s.getSelector().getType())
  )
}

from Assignment a
where isPartOfCr(a)
select a
