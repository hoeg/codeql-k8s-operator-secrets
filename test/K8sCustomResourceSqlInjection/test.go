package operator

import (
	"context"
	"database/sql"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// TableName is a named string type, the shape Kubernetes CRDs use heavily. It
// is a DefinedType rather than a BasicType, so it only becomes a
// CustomResourceValueSource through isStringishField's getUnderlyingType().
type TableName string

// MyCRSpec is the spec of the custom resource under test.
type MyCRSpec struct {
	// Filter is the plain string case.
	Filter string
	// Table is the named-string-type case.
	Table TableName
	// RawToken is the byte-slice case; ranging over it yields a `byte`, which
	// is numeric and therefore a SqlInjection::Sanitizer.
	RawToken []byte
}

// MyCR is registered with the scheme below, which is what makes it a
// CustomResourceType -- and hence its string fields CustomResourceValueSources.
type MyCR struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Spec MyCRSpec
}

// NotACR is structurally identical to MyCRSpec, so the Go extractor gives it
// the same Field entities: NotACR.Filter IS MyCRSpec.Filter as far as CodeQL is
// concerned. It is never registered, so only the base-type constraint in
// isCustomResourceFieldAccess keeps queryFromUnregisteredStruct out of the
// results.
type NotACR struct {
	Filter   string
	Table    TableName
	RawToken []byte
}

// SchemeBuilder registers MyCR. Without a real Register call,
// CustomResourceType is empty and this whole test proves nothing.
var SchemeBuilder = &scheme.Builder{}

func init() {
	SchemeBuilder.Register(&MyCR{})
}

// BAD: a string field of the CR is concatenated into a query passed to
// database/sql's DB.Query, whose argument 0 codeql/go-all models as a
// `sql-injection` sink and hence a SqlInjection::Sink.
func queryFromCrField(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Spec.Filter + "'")
}

// BAD: the same through DB.Exec, and through a *named* string field.
func execFromCrNamedStringField(db *sql.DB, cr *MyCR) {
	db.Exec("DROP TABLE " + string(cr.Spec.Table))
}

// GOOD: the query is a constant. Nothing flows from a custom resource into it.
func queryFromConstant(db *sql.DB) {
	db.Query("SELECT * FROM users WHERE name = 'admin'")
}

// GOOD: the CR field is passed as a bound query parameter rather than
// concatenated into the query string. Only argument 0 is the sink.
func queryWithBoundParameter(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = ?", cr.Spec.Filter)
}

// GOOD: `cr.Name` is promoted from metav1.ObjectMeta. Go gives structurally
// identical structs a single Field entity, so without isApiMachineryMetaField
// this would be a source on every Kubernetes object in every operator.
func queryFromObjectMetaName(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = '" + cr.Name + "'")
}

// GOOD: the base is an unregistered struct that shares MyCRSpec's Field
// entities; see the NotACR doc comment.
func queryFromUnregisteredStruct(db *sql.DB, x *NotACR) {
	db.Query("SELECT * FROM users WHERE name = '" + x.Filter + "'")
}

// GOOD: every byte of the CR's []byte field passes through `b`, whose type is
// `byte` -- numeric, hence a SqlInjection::Sanitizer and so a barrier under
// CrToSqlConfig::isBarrier. Drop isBarrier and this is reported.
func queryFromCrByteByByte(db *sql.DB, cr *MyCR) {
	q := "SELECT * FROM users WHERE name = '"
	for _, b := range cr.Spec.RawToken {
		q += string(b)
	}
	db.Query(q + "'")
}

// GOOD, and this used to be reported. The CR field reaches a MongoDB filter
// through the `Value` field of a bson.D element (a primitive.E), which is a
// BSON *value* position: a Go string there always marshals to a BSON string,
// where `$ne`, `$where` and nested documents are inert, and nothing
// concatenates it into query text. This is the shape that produced the
// percona-server-mongodb-operator false positives.
//
// Note what this costs: `NoSql::isAdditionalMongoTaintStep` -- the flow step
// this fixture was originally written to pin down, after it was once wired up
// under the wrong predicate name and silently did nothing -- is now unreachable
// in this query, because `bsonDocumentValue` barriers exactly the nodes that
// step starts from. Nothing in this test suite exercises it any more.
func mongoFindFromCrField(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	filter := bson.D{{Key: "name", Value: cr.Spec.Filter}}
	coll.Find(ctx, filter)
}

// GOOD: a constant Mongo filter.
func mongoFindFromConstant(ctx context.Context, coll *mongo.Collection) {
	filter := bson.D{{Key: "name", Value: "admin"}}
	coll.Find(ctx, filter)
}

// GOOD: the CR field is the value of a `bson.M` entry -- the map form of the
// case above, and the literal shape of the percona finding
// (`bson.M{"n": bson.M{"$in": hosts}}`). Nothing on this path builds query
// text, so the flow state never leaves `raw value`.
func mongoFindFromCrFieldInMapValue(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	coll.Find(ctx, bson.M{"name": cr.Spec.Filter})
}

// GOOD: a BSON value position stays inert even when a concatenation put the CR
// field there, so the flow state *does* reach `constructed query text` and only
// `bsonDocumentValue` keeps this quiet. Drop that barrier and this one is
// reported; the two cases above stay quiet either way, which is why this
// fixture is here.
func mongoFindFromConcatenatedValue(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	coll.Find(ctx, bson.M{"name": "prefix-" + cr.Spec.Filter})
}

// GOOD: a Postgres-style `$n` bind parameter. As with the `?` case above, the
// driver sends the value out of band and argument 0 is the only query string.
func queryWithNumberedBindParameter(db *sql.DB, cr *MyCR) {
	db.Query("SELECT * FROM users WHERE name = $1", cr.Spec.Filter)
}

// BAD: the statement is built with fmt.Sprintf in one function and executed in
// another. This is the shape of every real finding in postgres-operator,
// clickhouse-operator, schemahero and percona-xtradb-cluster-operator, and it
// is the reason "was this built by concatenation or fmt?" is tracked as flow
// state rather than tested at the sink: a sink-local test sees only
// `db.Exec(<a parameter>)` here and drops the finding.
func buildDropStatement(cr *MyCR) string {
	return fmt.Sprintf("DROP TABLE %s", cr.Spec.Filter)
}

func execBuiltStatement(db *sql.DB, cr *MyCR) {
	db.Exec(buildDropStatement(cr))
}

// GOOD, and deliberately so: the CR field is the *whole* statement, never
// concatenated or formatted into anything. An operator that does this hands
// over complete control of the statement, so this is a true positive the
// construction requirement gives up in exchange for the BSON-value fix. No
// operator in the 49-database corpus does it.
func execWholeCrFieldAsStatement(db *sql.DB, cr *MyCR) {
	db.Exec(string(cr.Spec.Table))
}

// GOOD: `%T` formats the argument's Go type name, never its contents, so
// nothing of the CR field reaches the statement even though fmt.Sprintf does
// build query text here. This is the shared format-verb barrier from
// Barriers.qll: drop `getAFormatVerbBarrierArgument()` from the configuration
// and this one is reported.
func execFormattedWithTypeVerb(db *sql.DB, cr *MyCR) {
	db.Exec(fmt.Sprintf("SELECT * FROM t WHERE c = '%T'", cr.Spec.Filter))
}

// GOOD: the same BSON value position reached by assignment rather than by a
// keyed literal -- `e.Value = ...` on a `bson.E`. This is the exact shape
// `NoSql::isAdditionalMongoTaintStep` models, and the branch of
// `bsonDocumentValue` that matches field writes is what keeps it quiet; the
// concatenation is there so the flow state reaches `constructed query text`
// and only that branch can stop the report.
func mongoFindFromAssignedEntryValue(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	var e bson.E
	e.Key = "name"
	e.Value = "prefix-" + cr.Spec.Filter
	coll.Find(ctx, bson.D{e})
}

// GOOD: the same BSON value position reached through a keyed element literal
// inside a `bson.D`, with the concatenation that pushes the flow state to
// `constructed query text` so that only a barrier can keep it quiet.
//
// This is the *literal* half of the field-write branch of `bsonDocumentValue`,
// and it is here because mutation testing found that branch was only half
// pinned. `mongoFindFromAssignedEntryValue` above exercises it through an
// assignment; nothing exercised it through a struct literal, which is the form
// every real driver call uses. The Go extractor models both as a `Write` to
// `primitive.E.Value`, so deleting that branch now reports both functions
// rather than one.
//
// `mongoFindFromCrField` uses this same literal shape without a concatenation,
// so it never reaches `constructed query text` and stays quiet whether or not
// any barrier exists -- which is why it pins nothing on its own.
func mongoFindFromConcatenatedEntryLiteralValue(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	coll.Find(ctx, bson.D{{Key: "name", Value: "prefix-" + cr.Spec.Filter}})
}
