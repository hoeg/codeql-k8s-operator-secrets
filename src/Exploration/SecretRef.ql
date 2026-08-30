/**
 * Exploration: struct types that embed a pointer to a
 * `k8s.io/api/core/v1.SecretKeySelector`, i.e. types that point at secret
 * material.
 */

import go
import K8sOperators

from StructTypeExpr ste, StructType st, PointerType pt
where
  st.hasField(_, pt) and
  pt.getBaseType() instanceof K8sSecretKeySelector and
  ste.getType() = st
select ste.getLocation()
