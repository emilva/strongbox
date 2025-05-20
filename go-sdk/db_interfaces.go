// Package strongbox provides the Go SDK for interacting with Strongbox services.
// This file defines interfaces for database interactions, primarily for DynamoDB.
package strongbox

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// DynamoDBAPI defines the interface for DynamoDB operations used by the SDK,
// primarily by the SecretsGroup implementation for storing and retrieving secret metadata
// and encrypted values. This allows for mocking the DynamoDB client in tests.
type DynamoDBAPI interface {
	// PutItem creates a new item or replaces an old item with a new item.
	// If an item that has the same primary key as the new item already exists
	// in the specified table, the new item completely replaces the existing item.
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	
	// GetItem returns a set of attributes for the item with the given primary key.
	// If there is no matching item, GetItem does not return any data and there will be no Item element in the response.
	GetItem(ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	
	// Query finds items based on primary key values. You can query any table or secondary index that has a composite primary key (a partition key and a sort key).
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
	
	// UpdateItem edits an existing item's attributes, or adds a new item to the table if it does not already exist.
	// You can put, delete, or add attribute values.
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	
	// DeleteItem deletes a single item in a table by primary key.
	DeleteItem(ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	
	// Scan returns one or more items and item attributes by accessing every item in a table or a secondary index.
	// To have DynamoDB return fewer items, you can provide a FilterExpression operation.
	Scan(ctx context.Context, params *dynamodb.ScanInput, optFns ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}
