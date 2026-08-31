// Package operator is the fixture for Diagnostics/CustomResourceCoverage.ql and
// for the claims its message makes about the other two queries.
//
// The whole point of this directory is what it does NOT contain: a call to
// scheme.Builder.Register or to runtime.Scheme.AddKnownTypes. MyCR below has
// every shape of a real custom resource, and the controller-runtime scheme
// package is vendored and referenced, but no registration call site exists, so
// CustomResourceType is empty here exactly as it is on rancher/fleet, velero,
// stakater/Reloader, kubernetes-replicator, wave and secrets-store-csi-driver.
//
// Three .qlref files run over this one database, and together they assert the
// three claims the diagnostic's message makes:
//
//   - CustomResourceCoverage.ql fires, with the message text pinned verbatim.
//   - K8sCustomResourceSqlInjection.ql is silent, and queryFromCustomResourceField
//     is why that silence is not vacuous: it is a textbook injection that only
//     goes unreported because CustomResourceValueSource has no CR type to anchor
//     on. Make that source CR-independent and this test fails.
//   - K8sSecretsLeak.ql still reports, because SecretMaterializationSink does not
//     depend on custom resource types. leakIntoEnvVarValue is reduced from
//     rancher/fleet's gitjob.go, the database that proved the old message wrong:
//     zero CR types, and two live EnvVar.Value findings.
//
// The pairing of leakIntoEnvVarValue with leakIntoCustomResourceField in one file
// is the assertion that matters. Both write the same secret byte slice through
// the same conversion; one is reported and one is not, and the difference is
// solely which half of SecretLeakSink the destination belongs to.
package operator

import (
	"database/sql"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// MyCRSpec is the spec half of the unregistered custom resource.
type MyCRSpec struct {
	// Filter is read into a SQL statement by queryFromCustomResourceField. It
	// would be a CustomResourceValueSource if MyCR were registered.
	Filter string
	// Token is written to by leakIntoCustomResourceField. It would be a
	// CustomResourceFieldSink if MyCR were registered.
	Token string
}

// MyCR is shaped exactly like a registered custom resource -- embedded TypeMeta
// and ObjectMeta, a Spec struct of plain string fields -- and is deliberately
// never registered.
type MyCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec MyCRSpec
}

// SchemeBuilder puts the controller-runtime scheme package into the database
// without ever calling Register on it.
//
// This is what stops the diagnostic from passing for the wrong reason. If the
// import were absent, SchemaBuilder would have no Function to match and the
// test would prove only that the vendored package is missing. With it present,
// the sole reason CustomResourceType is empty is the absence of a Register call
// site -- the real-world condition, where an operator registers its types
// through a shape the pack does not model.
var SchemeBuilder = &scheme.Builder{}

// BAD, and reported: secret material materialised as a literal
// environment-variable value.
//
// This is rancher/fleet's
// internal/cmd/controller/gitops/reconciler/gitjob.go:375 reduced to its
// skeleton -- an append of a corev1.EnvVar literal whose Value carries secret
// bytes. It is a SecretMaterializationSink, which is pinned by field qualified
// name and carries no custom-resource base constraint, so it is found here at
// full strength despite CustomResourceType being empty.
//
// This function is the whole reason the diagnostic's message was rewritten. The
// old text told a reader that K8sSecretsLeak "has no sinks here" and that its
// results were meaningless whenever this diagnostic fired, which would have had
// them discard this finding and the two real ones on fleet.
func leakIntoEnvVarValue(pod *corev1.PodSpec, secret *corev1.Secret) {
	pod.Containers[0].Env = append(pod.Containers[0].Env, corev1.EnvVar{
		Name:  "TOKEN",
		Value: string(secret.Data["k"]),
	})
}

// BAD in the code, but NOT reported: the same secret bytes written into a field
// of the custom resource.
//
// With MyCR registered this is a CustomResourceFieldSink and a finding. Here the
// CR half of SecretLeakSink is empty, so the leak is invisible. This is the
// coverage the diagnostic warns is lost, and it is why the message says the
// query's silence about custom-resource fields -- and only that silence -- is
// meaningless.
func leakIntoCustomResourceField(secret *corev1.Secret, cr *MyCR) {
	cr.Spec.Token = string(secret.Data["k"])
}

// NOT reported: a custom-resource string field concatenated straight into a SQL
// statement.
//
// Nothing sanitises this and the sink is a real database/sql query argument. It
// goes unreported for one reason only: CustomResourceValueSource requires
// isCustomResourceFieldAccess, which requires a CustomResourceType, and there is
// none. That makes K8sCustomResourceSqlInjection's empty result on this database
// the absence of sources rather than the absence of vulnerabilities, which is
// exactly what the diagnostic tells the reader to conclude.
func queryFromCustomResourceField(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Spec.Filter + "'")
}
