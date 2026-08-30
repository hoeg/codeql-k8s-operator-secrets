/**
 * Exploration: which types does this operator register with a scheme?
 * Selects each registration call site together with the registered type.
 */

import go
import K8sOperators

from CallExpr ce, Function f, Expr e, PointerType pt
where
  f = ce.getTarget() and
  (f instanceof APISchemaBuilder or f instanceof SchemaBuilder) and
  e = ce.getAnArgument() and
  pt = e.getType()
select ce.getLocation(), pt.getBaseType()
