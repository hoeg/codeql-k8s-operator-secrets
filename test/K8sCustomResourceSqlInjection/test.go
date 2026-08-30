package operator

import (
	"context"
	"database/sql"

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

// BAD: a CR string field reaches a MongoDB filter through the `Value` field of
// a bson.D element (a primitive.E). Flow from `cr.Spec.Filter` to the
// mongo.Collection.Find nosql-injection sink exists only if
// CrToSqlConfig's flow-step predicate really is named `isAdditionalFlowStep`;
// under the old `isAdditionalTaintStep` name it compiles as dead code and this
// finding silently disappears.
func mongoFindFromCrField(ctx context.Context, coll *mongo.Collection, cr *MyCR) {
	filter := bson.D{{Key: "name", Value: cr.Spec.Filter}}
	coll.Find(ctx, filter)
}

// GOOD: a constant Mongo filter.
func mongoFindFromConstant(ctx context.Context, coll *mongo.Collection) {
	filter := bson.D{{Key: "name", Value: "admin"}}
	coll.Find(ctx, filter)
}
