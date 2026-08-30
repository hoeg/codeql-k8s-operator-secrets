// Stub of go.mongodb.org/mongo-driver/bson/primitive.
package primitive

// E is a stub of primitive.E, a single BSON document element. The go-all
// library's NoSql::isAdditionalMongoTaintStep keys off writes to the `Value`
// field of a value whose type is `primitive.E`.
type E struct {
	Key   string
	Value interface{}
}

// D is a stub of primitive.D, an ordered BSON document.
type D []E

// M is a stub of primitive.M, an unordered BSON document.
type M map[string]interface{}
