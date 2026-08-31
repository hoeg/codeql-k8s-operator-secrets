// Package operator is the fixture for the custom-resource *Status* source
// exclusion in K8sOperators.qll (isCustomResourceStatusType /
// isCustomResourceStatusFieldAccess, used by CustomResourceValueSource).
//
// It lives in a test directory of its own rather than in
// test/K8sCustomResourceSqlInjection because it needs a custom resource with a
// Status struct, and adding one to that CR would change the type graph -- and so
// potentially the results -- of every fixture already in that file.
//
// The query run over it is the SQL-injection query, because
// CustomResourceValueSource is the source class of that query and of no other in
// the pack. The secrets-leak query cannot exercise this exclusion at all: its
// sources are Secret values, and a custom-resource field is a *sink* there, not a
// source.
package operator

import (
	"database/sql"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// MyCRSpec is the spec half of the custom resource: the part a user writes in
// the manifest, and therefore the part that is attacker-controlled.
type MyCRSpec struct {
	Filter string
}

// MyCRCondition is a struct nested *under* the status. Its own name does not end
// in "Status", so isCustomResourceStatusType does not hold of it, and the
// exclusion -- which only tests the type that directly declares the field --
// does not reach the fields it declares. That is the third documented limit of
// the approximation, and queryFromStatusCondition below pins it: the limit is
// asserted in a doc comment, so it needs a fixture or a later reader cannot tell
// whether it is still true.
type MyCRCondition struct {
	Message string
}

// MyCRStatus is the status half. The API server strips any user-supplied
// `status` on create and update whenever the CRD declares the status
// subresource, so its fields are written by the operator, not by the manifest
// author, and are not attacker-controlled.
//
// The CRD manifest is not in the CodeQL database, so isCustomResourceStatusType
// stands in for it by matching the *type name* against "%Status". This struct is
// therefore named MyCRStatus deliberately: rename it to MyCRState and the
// exclusion stops applying, which is exactly the second documented limit.
type MyCRStatus struct {
	LastError  string
	Conditions []MyCRCondition
}

// MyCR is registered with the scheme below, which is what makes it a
// CustomResourceType and its string fields CustomResourceValueSources.
type MyCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec   MyCRSpec
	Status MyCRStatus
}

// SchemeBuilder registers MyCR. Without a real Register call, CustomResourceType
// is empty and this whole test proves nothing -- every fixture below would be
// quiet for the wrong reason.
var SchemeBuilder = &scheme.Builder{}

func init() {
	SchemeBuilder.Register(&MyCR{})
}

// BAD: a *spec* field concatenated into a query.
//
// This is the control for queryFromStatusField. It proves that the CR is
// registered, that CustomResourceValueSource fires on this custom resource, and
// that the exclusion is scoped to the status rather than sanitising the whole
// object -- both functions read a plain string field of the same MyCR through
// the same `+` into the same sink, and the only difference between them is which
// half of the CR the field sits in.
func queryFromSpecField(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Spec.Filter + "'")
}

// GOOD: the same query built from a *status* field, which the API server
// overwrites from the operator's own reconcile output rather than from the
// manifest. Not a source, so nothing flows and nothing is reported.
//
// Delete isCustomResourceStatusFieldAccess from CustomResourceValueSource and
// this function is reported.
func queryFromStatusField(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Status.LastError + "'")
}

// BAD, and deliberately so: a field of a struct nested one level under the
// status. The base of the field read is a MyCRCondition, whose name does not end
// in "Status", so the exclusion does not hold and the read stays a source. See
// the MyCRCondition doc comment; this is the documented under-approximation, not
// an accident, and this fixture is what will fail if someone widens the
// exclusion to everything reachable from a status type without meaning to.
func queryFromStatusCondition(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Status.Conditions[0].Message + "'")
}
