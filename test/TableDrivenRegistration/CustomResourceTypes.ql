/**
 * @name Registered custom resource types
 * @description Every `CustomResourceType` in the database, by package and name.
 *              This is a unit test for the third disjunct of
 *              `CustomResourceType` -- the one backed by
 *              `SchemeRegistrationFlow` -- and not a security query. A table is
 *              used rather than the security queries alone so that the negative
 *              cases show up as a named absence from a list of types, rather
 *              than as the absence of a path from a path-problem `.expected`
 *              where a type could go missing for a dozen unrelated reasons.
 *
 *              The package column is load-bearing: it is what makes the
 *              `k8s.io/` exclusion visible. Without it, `Secret` being absent
 *              could not be told apart from `Secret` never having been a
 *              candidate.
 * @kind table
 * @id go/test/registered-custom-resource-types
 */

import go
import K8sOperators

from CustomResourceType t, string pkg, string name
where t.hasQualifiedName(pkg, name)
select pkg, name
