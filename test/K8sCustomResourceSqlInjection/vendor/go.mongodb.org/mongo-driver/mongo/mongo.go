// Stub of go.mongodb.org/mongo-driver/mongo.
package mongo

import "context"

// Cursor is a stub of mongo.Cursor.
type Cursor struct{}

// SingleResult is a stub of mongo.SingleResult.
type SingleResult struct{}

// Collection is a stub of mongo.Collection. `Find`/`FindOne` argument 1 is
// modelled by codeql/go-all as a `nosql-injection` sink.
type Collection struct{}

// Find is a stub of mongo.Collection.Find.
func (c *Collection) Find(ctx context.Context, filter interface{}, opts ...interface{}) (*Cursor, error) {
	return nil, nil
}

// FindOne is a stub of mongo.Collection.FindOne.
func (c *Collection) FindOne(ctx context.Context, filter interface{}, opts ...interface{}) *SingleResult {
	return nil
}
