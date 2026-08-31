/**
 * @name Guarded EnvVar.Value reads
 * @description Every read of `k8s.io/api/core/v1.EnvVar.Value` that
 *              `Barriers.qll` treats as guarded by an equality check on the
 *              corresponding `EnvVar.Name`. This is a unit test for
 *              `guardedEnvVarValueRead`, not a security query: it is here so
 *              that a shape which must *not* be barriered shows up as a named
 *              absence rather than as a missing path in a path-problem
 *              `.expected`.
 * @kind table
 * @id go/test/guarded-envvar-value-read
 */

import go
import Barriers

from DataFlow::Node read, FuncDef enclosing
where
  read = getAGuardedEnvVarValueRead() and
  enclosing = read.getRoot()
select enclosing.getName(), read
