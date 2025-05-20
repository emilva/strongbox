// Package strongbox provides the Go SDK for interacting with Strongbox services.
// This file contains the implementation of the SecretsGroup interface, which
// handles operations on secrets within a specific group.
package strongbox

import (
	"context"
	"encoding/json" // For JSON handling
	"errors"        // For errors.As
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddbsvc "github.com/aws/aws-sdk-go-v2/service/dynamodb" // Alias to avoid conflict
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	kmssvc "github.com/aws/aws-sdk-go-v2/service/kms"

	"go-sdk/exceptions"
	"go-sdk/types"
)

// DefaultSecretsGroup implements the SecretsGroup and SimpleSecretsGroup interfaces.
// It uses an underlying KMS key (via KMSAPI) for cryptographic operations and
// DynamoDB (via DynamoDBAPI) for storing secret metadata and encrypted values.
type DefaultSecretsGroup struct {
	// Identifier holds the name and region of this secrets group.
	Identifier types.SecretsGroupIdentifier
	// kmsClient is the client used for KMS operations like Encrypt/Decrypt.
	kmsClient KMSAPI
	// dynamoClient is the client used for DynamoDB operations.
	dynamoClient DynamoDBAPI
	// tableName is the DynamoDB table where secrets for this group are stored.
	tableName string
	// Region is the AWS region of this secrets group.
	Region string
}

// NewDefaultSecretsGroup creates a new instance of DefaultSecretsGroup.
// This constructor is typically called by a SecretsGroupManager.
//
// identifier: The identifier for this secrets group.
// kmsClient: An initialized KMS client (KMSAPI implementation).
// dynamoClient: An initialized DynamoDB client (DynamoDBAPI implementation).
// tableName: The name of the DynamoDB table for storing secrets.
// region: The AWS region this secrets group operates in.
func NewDefaultSecretsGroup(
	identifier types.SecretsGroupIdentifier,
	kmsClient KMSAPI,
	dynamoClient DynamoDBAPI,
	tableName string,
	region string,
) *DefaultSecretsGroup {
	return &DefaultSecretsGroup{
		Identifier:   identifier,
		kmsClient:    kmsClient,
		dynamoClient: dynamoClient,
		tableName:    tableName,
		Region:       region,
	}
}

// dynamoSecretItem is an internal struct representing the schema for secret items
// stored in DynamoDB. Fields are tagged for DynamoDB attribute value marshaling.
type dynamoSecretItem struct {
	SecretName               string `dynamodbav:"SecretName"` // Primary key (Partition Key)
	Version                  int64  `dynamodbav:"Version"`    // Primary key (Sort Key)
	EncryptedValue           []byte `dynamodbav:"EncryptedValue"`
	SecretType               string `dynamodbav:"SecretType"`
	Comment                  string `dynamodbav:"Comment,omitempty"`
	NotBefore                string `dynamodbav:"NotBefore,omitempty"` // ISO8601 string
	NotAfter                 string `dynamodbav:"NotAfter,omitempty"`  // ISO8601 string
	State                    string `dynamodbav:"State"`
	CreatedAt                string `dynamodbav:"CreatedAt"`         // ISO8601 string
	LastUpdatedAt            string `dynamodbav:"LastUpdatedAt"`     // ISO8601 string
	KMSEncryptionContextJSON string `dynamodbav:"KMSEncryptionContextJSON"`
	UserData                 map[string]string `dynamodbav:"UserData,omitempty"`
}

// rawSecretEntryFromDynamoItem is a helper function to convert a dynamoSecretItem
// (retrieved from DynamoDB) into a types.RawSecretEntry for SDK use.
// It handles parsing of timestamp strings into time.Time objects.
func rawSecretEntryFromDynamoItem(item dynamoSecretItem) types.RawSecretEntry {
	createdAt, _ := time.Parse(time.RFC3339Nano, item.CreatedAt) // Ignoring parse error for brevity in example
	lastUpdatedAt, _ := time.Parse(time.RFC3339Nano, item.LastUpdatedAt) // Ignoring parse error

	metadata := types.SecretMetadata{
		Identifier:              types.SecretIdentifier{Name: item.SecretName},
		Version:                 item.Version,
		State:                   item.State,
		Comment:                 item.Comment,
		KMSEncryptionContextJSON: item.KMSEncryptionContextJSON,
		CreatedAt:               createdAt,
		LastUpdatedAt:           lastUpdatedAt,
		UserData:                item.UserData, 
		SecretType:              item.SecretType,
	}
	if item.NotBefore != "" {
		tnb, err := time.Parse(time.RFC3339Nano, item.NotBefore)
		if err == nil {
			metadata.NotBefore = &tnb
		}
		// else: log or handle parse error for NotBefore if necessary
	}
	if item.NotAfter != "" {
		tna, err := time.Parse(time.RFC3339Nano, item.NotAfter)
		if err == nil {
			metadata.NotAfter = &tna
		}
		// else: log or handle parse error for NotAfter if necessary
	}

	return types.RawSecretEntry{
		Identifier:    types.SecretIdentifier{Name: item.SecretName},
		Version:       item.Version,
		EncryptedData: item.EncryptedValue, 
		Metadata:      metadata,
	}
}

// Create creates the first version (version 1) of a new secret within the group.
// It encrypts the secret value using the group's KMS key and stores it in DynamoDB.
// A ConditionalCheckFailedException (wrapped as exceptions.ErrAlreadyExists) is returned
// if a secret with the same name and version 1 already exists.
//
// ctx: Context for the API operation.
// newSecretEntry: Contains the details of the secret to be created.
// Returns a RawSecretEntry representing the created secret or an error.
func (sg *DefaultSecretsGroup) Create(ctx context.Context, newSecretEntry types.NewSecretEntry) (types.RawSecretEntry, error) {
	if newSecretEntry.Identifier.Name == "" {
		return types.RawSecretEntry{}, fmt.Errorf("NewSecretEntry.Identifier.Name cannot be empty")
	}
	if len(newSecretEntry.Value) == 0 {
		return types.RawSecretEntry{}, fmt.Errorf("NewSecretEntry.Value cannot be empty")
	}

	kmsKeyAlias := fmt.Sprintf("alias/strongbox/%s/%s", sg.Identifier.Region, sg.Identifier.Name)
	now := time.Now().UTC()
	initialVersion := int64(1)

	encryptionContext := map[string]string{
		"StrongboxSecretName": newSecretEntry.Identifier.Name,
		"StrongboxGroupName":  sg.Identifier.Name,
		"StrongboxRegion":     sg.Identifier.Region,
		"StrongboxVersion":    fmt.Sprintf("%d", initialVersion),
	}
	encryptionContextJsonBytes, err := json.Marshal(encryptionContext)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal encryption context: %w", err)
	}

	encryptInput := &kmssvc.EncryptInput{
		KeyId:             aws.String(kmsKeyAlias),
		Plaintext:         newSecretEntry.Value,
		EncryptionContext: encryptionContext,
	}
	encryptOutput, err := sg.kmsClient.Encrypt(ctx, encryptInput)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("KMS encryption failed for secret %s: %w", newSecretEntry.Identifier.Name, err)
	}
	encryptedValue := encryptOutput.CiphertextBlob

	item := dynamoSecretItem{
		SecretName:               newSecretEntry.Identifier.Name,
		Version:                  initialVersion,
		EncryptedValue:           encryptedValue,
		SecretType:               newSecretEntry.SecretType, 
		Comment:                  newSecretEntry.Comment,
		State:                    string(types.StateEnabled),
		CreatedAt:                now.Format(time.RFC3339Nano),
		LastUpdatedAt:            now.Format(time.RFC3339Nano),
		KMSEncryptionContextJSON: string(encryptionContextJsonBytes), 
		UserData:                 newSecretEntry.UserData,
	}
	if newSecretEntry.NotBefore != nil {
		item.NotBefore = newSecretEntry.NotBefore.Format(time.RFC3339Nano)
	}
	if newSecretEntry.NotAfter != nil {
		item.NotAfter = newSecretEntry.NotAfter.Format(time.RFC3339Nano)
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal secret item for DynamoDB: %w", err)
	}

	putItemInput := &ddbsvc.PutItemInput{
		TableName:           aws.String(sg.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(SecretName) AND attribute_not_exists(Version)"),
	}
	_, err = sg.dynamoClient.PutItem(ctx, putItemInput)
	if err != nil {
		var condCheckFailed *ddbtypes.ConditionalCheckFailedException
		if errors.As(err, &condCheckFailed) {
			return types.RawSecretEntry{}, fmt.Errorf("secret %s version %d already exists: %w", item.SecretName, item.Version, exceptions.ErrAlreadyExists)
		}
		return types.RawSecretEntry{}, fmt.Errorf("DynamoDB PutItem failed for secret %s: %w", item.SecretName, err)
	}
	return rawSecretEntryFromDynamoItem(item), nil
}

// AddVersion creates a new version for an existing secret.
// It first queries for the latest existing version to determine the new version number.
// The secret value is encrypted using the group's KMS key.
// A ConditionalCheckFailedException (wrapped as exceptions.ErrConflict) is returned if an item
// with the same SecretName and new Version already exists, indicating a possible concurrent operation.
// Returns exceptions.ErrNotFound if the secret name does not exist.
//
// ctx: Context for the API operation.
// newSecretEntry: Contains the details of the new secret version. Identifier.Name must match an existing secret.
// Returns a RawSecretEntry representing the new secret version or an error.
func (sg *DefaultSecretsGroup) AddVersion(ctx context.Context, newSecretEntry types.NewSecretEntry) (types.RawSecretEntry, error) {
	if newSecretEntry.Identifier.Name == "" {
		return types.RawSecretEntry{}, fmt.Errorf("NewSecretEntry.Identifier.Name cannot be empty for AddVersion")
	}
	if len(newSecretEntry.Value) == 0 {
		return types.RawSecretEntry{}, fmt.Errorf("NewSecretEntry.Value cannot be empty for AddVersion")
	}

	nameAV, err := attributevalue.Marshal(newSecretEntry.Identifier.Name)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal secret name for query: %w", err)
	}
	queryInput := &ddbsvc.QueryInput{
		TableName:              aws.String(sg.tableName),
		KeyConditionExpression: aws.String("SecretName = :nameVal"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":nameVal": nameAV,
		},
		ScanIndexForward: aws.Bool(false), 
		Limit:            aws.Int32(1),
	}
	queryOutput, err := sg.dynamoClient.Query(ctx, queryInput)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to query latest version for secret %s: %w", newSecretEntry.Identifier.Name, err)
	}

	if len(queryOutput.Items) == 0 {
		return types.RawSecretEntry{}, fmt.Errorf("secret %s not found, cannot add version: %w", newSecretEntry.Identifier.Name, exceptions.ErrNotFound)
	}

	var latestVersionItem dynamoSecretItem
	err = attributevalue.UnmarshalMap(queryOutput.Items[0], &latestVersionItem)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to unmarshal latest version for secret %s: %w", newSecretEntry.Identifier.Name, err)
	}
	currentMaxVersion := latestVersionItem.Version
	
	newVersion := currentMaxVersion + 1
	now := time.Now().UTC()

	kmsKeyAlias := fmt.Sprintf("alias/strongbox/%s/%s", sg.Identifier.Region, sg.Identifier.Name)
	encryptionContext := map[string]string{
		"StrongboxSecretName": newSecretEntry.Identifier.Name,
		"StrongboxGroupName":  sg.Identifier.Name,
		"StrongboxRegion":     sg.Identifier.Region,
		"StrongboxVersion":    fmt.Sprintf("%d", newVersion),
	}
	encryptionContextJsonBytes, err := json.Marshal(encryptionContext)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal encryption context for AddVersion: %w", err)
	}

	encryptInput := &kmssvc.EncryptInput{
		KeyId:             aws.String(kmsKeyAlias),
		Plaintext:         newSecretEntry.Value,
		EncryptionContext: encryptionContext,
	}
	encryptOutput, err := sg.kmsClient.Encrypt(ctx, encryptInput)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("KMS encryption failed for AddVersion of secret %s: %w", newSecretEntry.Identifier.Name, err)
	}
	encryptedValue := encryptOutput.CiphertextBlob

	item := dynamoSecretItem{
		SecretName:               newSecretEntry.Identifier.Name,
		Version:                  newVersion,
		EncryptedValue:           encryptedValue,
		SecretType:               newSecretEntry.SecretType, 
		Comment:                  newSecretEntry.Comment,
		State:                    string(types.StateEnabled), 
		CreatedAt:                now.Format(time.RFC3339Nano),
		LastUpdatedAt:            now.Format(time.RFC3339Nano),
		KMSEncryptionContextJSON: string(encryptionContextJsonBytes),
		UserData:                 newSecretEntry.UserData,
	}
	if newSecretEntry.NotBefore != nil {
		item.NotBefore = newSecretEntry.NotBefore.Format(time.RFC3339Nano)
	}
	if newSecretEntry.NotAfter != nil {
		item.NotAfter = newSecretEntry.NotAfter.Format(time.RFC3339Nano)
	}

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal secret item for DynamoDB (AddVersion): %w", err)
	}
	
	putItemInput := &ddbsvc.PutItemInput{
		TableName:           aws.String(sg.tableName),
		Item:                av,
		ConditionExpression: aws.String("attribute_not_exists(Version)"), 
	}
	_, err = sg.dynamoClient.PutItem(ctx, putItemInput)
	if err != nil {
		var condCheckFailed *ddbtypes.ConditionalCheckFailedException
		if errors.As(err, &condCheckFailed) {
			return types.RawSecretEntry{}, fmt.Errorf("version %d for secret %s likely created by concurrent operation: %w", newVersion, item.SecretName, exceptions.ErrConflict)
		}
		return types.RawSecretEntry{}, fmt.Errorf("DynamoDB PutItem failed for secret %s version %d (AddVersion): %w", item.SecretName, newVersion, err)
	}

	return rawSecretEntryFromDynamoItem(item), nil
}

// Update modifies the metadata of an existing secret version.
// It does not change the secret's encrypted value.
// Fields that can be updated include Comment, State, NotBefore, NotAfter, and UserData.
// LastUpdatedAt is always updated to the current time.
//
// ctx: Context for the API operation.
// secretMetadata: Contains the metadata to update. Identifier.Name and Version must specify an existing secret version.
// Returns a RawSecretEntry with the fully updated metadata or an error.
// Returns exceptions.ErrNotFound if the specified secret version does not exist.
func (sg *DefaultSecretsGroup) Update(ctx context.Context, secretMetadata types.SecretMetadata) (types.RawSecretEntry, error) {
	if secretMetadata.Identifier.Name == "" {
		return types.RawSecretEntry{}, fmt.Errorf("SecretMetadata.Identifier.Name cannot be empty for Update")
	}
	if secretMetadata.Version <= 0 {
		return types.RawSecretEntry{}, fmt.Errorf("SecretMetadata.Version must be > 0 for Update")
	}

	keyMap, err := attributevalue.MarshalMap(map[string]interface{}{
		"SecretName": secretMetadata.Identifier.Name,
		"Version":    secretMetadata.Version,
	})
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to marshal key for UpdateItem: %w", err)
	}
	
	updateExprParts := []string{}
	exprAttrValues := map[string]ddbtypes.AttributeValue{}
	exprAttrNames := map[string]string{} 

	exprAttrValues[":lutVal"] = &ddbtypes.AttributeValueMemberS{Value: time.Now().UTC().Format(time.RFC3339Nano)}
	updateExprParts = append(updateExprParts, "LastUpdatedAt = :lutVal")
	
	updateExprParts = append(updateExprParts, "Comment = :cmtVal")
	exprAttrValues[":cmtVal"] = &ddbtypes.AttributeValueMemberS{Value: secretMetadata.Comment}
	
	if secretMetadata.State != "" { 
		exprAttrNames["#S"] = "State" 
		updateExprParts = append(updateExprParts, "#S = :stateVal")
		exprAttrValues[":stateVal"] = &ddbtypes.AttributeValueMemberS{Value: secretMetadata.State}
	}

	if secretMetadata.NotBefore != nil {
		updateExprParts = append(updateExprParts, "NotBefore = :nbVal")
		exprAttrValues[":nbVal"] = &ddbtypes.AttributeValueMemberS{Value: secretMetadata.NotBefore.Format(time.RFC3339Nano)}
	} 

	if secretMetadata.NotAfter != nil {
		updateExprParts = append(updateExprParts, "NotAfter = :naVal")
		exprAttrValues[":naVal"] = &ddbtypes.AttributeValueMemberS{Value: secretMetadata.NotAfter.Format(time.RFC3339Nano)}
	} 

	if secretMetadata.UserData != nil { 
		userDataAV, errMarshalUD := attributevalue.MarshalMap(secretMetadata.UserData)
		if errMarshalUD == nil { 
			updateExprParts = append(updateExprParts, "UserData = :udVal")
			exprAttrValues[":udVal"] = &ddbtypes.AttributeValueMemberM{Value: userDataAV}
		}
	}
	
	updateExpression := "SET " + strings.Join(updateExprParts, ", ")

	updateItemInput := &ddbsvc.UpdateItemInput{
		TableName:                 aws.String(sg.tableName),
		Key:                       keyMap,
		UpdateExpression:          aws.String(updateExpression),
		ExpressionAttributeValues: exprAttrValues,
		ConditionExpression:       aws.String("attribute_exists(SecretName) AND attribute_exists(Version)"),
		ReturnValues:              ddbtypes.ReturnValueAllNew,
	}
    if len(exprAttrNames) > 0 {
        updateItemInput.ExpressionAttributeNames = exprAttrNames
    }

	updateOutput, err := sg.dynamoClient.UpdateItem(ctx, updateItemInput)
	if err != nil {
		var condCheckFailed *ddbtypes.ConditionalCheckFailedException
		if errors.As(err, &condCheckFailed) {
			return types.RawSecretEntry{}, fmt.Errorf("secret %s version %d not found for update: %w", secretMetadata.Identifier.Name, secretMetadata.Version, exceptions.ErrNotFound)
		}
		return types.RawSecretEntry{}, fmt.Errorf("DynamoDB UpdateItem failed for secret %s v%d: %w", secretMetadata.Identifier.Name, secretMetadata.Version, err)
	}

	var updatedItem dynamoSecretItem
	err = attributevalue.UnmarshalMap(updateOutput.Attributes, &updatedItem)
	if err != nil {
		return types.RawSecretEntry{}, fmt.Errorf("failed to unmarshal updated item from DynamoDB: %w", err)
	}

	return rawSecretEntryFromDynamoItem(updatedItem), nil
}

// Delete removes all versions of a specific secret from the group.
// This operation queries for all versions of the secret and then deletes each one individually.
// It is idempotent: if the secret (or some of its versions) does not exist, it will not return an error.
//
// ctx: Context for the API operation.
// secretIdentifier: The identifier of the secret to delete.
// Returns an error if any part of the deletion process fails for an existing version.
func (sg *DefaultSecretsGroup) Delete(ctx context.Context, secretIdentifier types.SecretIdentifier) error {
	if secretIdentifier.Name == "" {
		return fmt.Errorf("secret identifier name cannot be empty for delete")
	}

	var allKeysToDelete []map[string]ddbtypes.AttributeValue
	var lastEvaluatedKey map[string]ddbtypes.AttributeValue
	
	nameAV, err := attributevalue.Marshal(secretIdentifier.Name)
	if err != nil { 
		return fmt.Errorf("failed to marshal secret name for delete query: %w", err)
	}

	for {
		queryInput := &ddbsvc.QueryInput{
			TableName:              aws.String(sg.tableName),
			KeyConditionExpression: aws.String("SecretName = :nameVal"),
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":nameVal": nameAV,
			},
			ProjectionExpression: aws.String("SecretName, Version"), 
			ExclusiveStartKey:    lastEvaluatedKey,
		}

		queryOutput, err := sg.dynamoClient.Query(ctx, queryInput)
		if err != nil {
			return fmt.Errorf("failed to query versions for secret %s during delete: %w", secretIdentifier.Name, err)
		}

		for _, itemMap := range queryOutput.Items {
			if itemMap["SecretName"] == nil || itemMap["Version"] == nil {
				continue 
			}
			keyToDelete := map[string]ddbtypes.AttributeValue{
				"SecretName": itemMap["SecretName"],
				"Version":    itemMap["Version"],
			}
			allKeysToDelete = append(allKeysToDelete, keyToDelete)
		}

		lastEvaluatedKey = queryOutput.LastEvaluatedKey
		if lastEvaluatedKey == nil {
			break
		}
	}

	if len(allKeysToDelete) == 0 {
		return nil 
	}

	for _, keyMap := range allKeysToDelete {
		deleteItemInput := &ddbsvc.DeleteItemInput{
			TableName: aws.String(sg.tableName),
			Key:       keyMap,
		}
		_, err := sg.dynamoClient.DeleteItem(ctx, deleteItemInput)
		if err != nil {
			var versionToDeleteValue string
			if vAttr, ok := keyMap["Version"].(*ddbtypes.AttributeValueMemberN); ok {
				versionToDeleteValue = vAttr.Value
			} else {
				versionToDeleteValue = "unknown"
			}
			return fmt.Errorf("failed to delete version %s for secret %s: %w", versionToDeleteValue, secretIdentifier.Name, err)
		}
	}
	return nil 
}


// getSecretVersionFromDB is an internal helper to fetch a specific secret version from DynamoDB
// and unmarshal it into a dynamoSecretItem struct.
func (sg *DefaultSecretsGroup) getSecretVersionFromDB(ctx context.Context, secretIdentifier types.SecretIdentifier, version int64) (*dynamoSecretItem, error) {
	key, err := attributevalue.MarshalMap(map[string]interface{}{
		"SecretName": secretIdentifier.Name,
		"Version":    version,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key for GetItem: %w", err)
	}

	getItemInput := &ddbsvc.GetItemInput{
		TableName: aws.String(sg.tableName),
		Key:       key,
	}

	getItemOutput, err := sg.dynamoClient.GetItem(ctx, getItemInput)
	if err != nil {
		return nil, fmt.Errorf("DynamoDB GetItem failed for secret %s version %d: %w", secretIdentifier.Name, version, err)
	}

	if getItemOutput.Item == nil {
		return nil, exceptions.ErrNotFound 
	}

	var item dynamoSecretItem
	err = attributevalue.UnmarshalMap(getItemOutput.Item, &item)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DynamoDB item for secret %s version %d: %w", secretIdentifier.Name, version, err)
	}

	return &item, nil
}

// Decrypt decrypts the EncryptedData within a RawSecretEntry using the group's KMS key
// and the KMSEncryptionContextJSON stored in the secret's metadata.
// It performs integrity checks to ensure the provided entry matches the expected identifier and version.
//
// ctx: Context for the API operation.
// rawSecretEntry: The secret entry containing encrypted data and metadata.
// expectedSecretIdentifier: The identifier of the secret expected to be decrypted.
// expectedVersion: The version of the secret expected to be decrypted.
// Returns a SecretEntry with the plaintext SecretValue or an error if decryption or validation fails.
func (sg *DefaultSecretsGroup) Decrypt(ctx context.Context, rawSecretEntry types.RawSecretEntry, expectedSecretIdentifier types.SecretIdentifier, expectedVersion int64) (types.SecretEntry, error) {
	if rawSecretEntry.Identifier.Name != expectedSecretIdentifier.Name || rawSecretEntry.Version != expectedVersion {
		return types.SecretEntry{}, fmt.Errorf("identifier or version mismatch: expected %s v%d, got %s v%d: %w",
			expectedSecretIdentifier.Name, expectedVersion,
			rawSecretEntry.Identifier.Name, rawSecretEntry.Version,
			exceptions.ErrIntegrity)
	}

	if rawSecretEntry.Metadata.KMSEncryptionContextJSON == "" {
		return types.SecretEntry{}, fmt.Errorf("KMSEncryptionContextJSON is missing from secret metadata for %s v%d: %w",
			rawSecretEntry.Identifier.Name, rawSecretEntry.Version, exceptions.ErrIntegrity)
	}

	var parsedEncryptionContext map[string]string
	err := json.Unmarshal([]byte(rawSecretEntry.Metadata.KMSEncryptionContextJSON), &parsedEncryptionContext)
	if err != nil {
		return types.SecretEntry{}, fmt.Errorf("failed to unmarshal KMSEncryptionContextJSON for %s v%d: %w",
			rawSecretEntry.Identifier.Name, rawSecretEntry.Version, err)
	}
	
	kmsKeyAlias := fmt.Sprintf("alias/strongbox/%s/%s", sg.Identifier.Region, sg.Identifier.Name)

	decryptInput := &kmssvc.DecryptInput{
		CiphertextBlob:    rawSecretEntry.EncryptedData,
		EncryptionContext: parsedEncryptionContext,
		KeyId:             aws.String(kmsKeyAlias), 
	}
	
	decryptOutput, err := sg.kmsClient.Decrypt(ctx, decryptInput)
	if err != nil {
		return types.SecretEntry{}, fmt.Errorf("KMS decryption failed for secret %s v%d: %w",
			rawSecretEntry.Identifier.Name, rawSecretEntry.Version, err)
	}

	return types.SecretEntry{
		Identifier:  rawSecretEntry.Identifier,
		Version:     rawSecretEntry.Version,
		SecretValue: decryptOutput.Plaintext,
		SecretType:  rawSecretEntry.Metadata.SecretType, 
		Metadata:    rawSecretEntry.Metadata,
	}, nil
}

// DecryptEvenIfNotActive decrypts a secret version without checking its active status (State, NotBefore, NotAfter).
// This method is intended for administrative or recovery purposes where access to an inactive secret is required.
// It otherwise performs the same decryption and integrity checks as the Decrypt method.
//
// ctx: Context for the API operation.
// rawSecretEntry: The secret entry containing encrypted data and metadata.
// expectedSecretIdentifier: The identifier of the secret expected to be decrypted.
// expectedVersion: The version of the secret expected to be decrypted.
// Returns a SecretEntry with the plaintext SecretValue or an error.
func (sg *DefaultSecretsGroup) DecryptEvenIfNotActive(ctx context.Context, rawSecretEntry types.RawSecretEntry, expectedSecretIdentifier types.SecretIdentifier, expectedVersion int64) (types.SecretEntry, error) {
	return sg.Decrypt(ctx, rawSecretEntry, expectedSecretIdentifier, expectedVersion)
}


// GetActive retrieves a specific version of a secret, decrypts it, and returns it,
// but only if the secret version is currently "active".
// An active secret is one that is ENABLED, and if NotBefore/NotAfter timestamps are set,
// the current time must be within that validity window.
//
// ctx: Context for the API operation.
// secretIdentifier: The name of the secret.
// targetVersion: The specific version to retrieve.
// Returns the decrypted SecretEntry, a boolean indicating if found and active (true if successful, false otherwise),
// and an error if the operation failed or if the secret is not active (exceptions.ErrSecretNotActive).
// If the secret/version is not found, it returns (zero SecretEntry, false, nil).
func (sg *DefaultSecretsGroup) GetActive(ctx context.Context, secretIdentifier types.SecretIdentifier, targetVersion int64) (types.SecretEntry, bool, error) {
	item, err := sg.getSecretVersionFromDB(ctx, secretIdentifier, targetVersion)
	if err != nil {
		if errors.Is(err, exceptions.ErrNotFound) {
			return types.SecretEntry{}, false, nil 
		}
		return types.SecretEntry{}, false, fmt.Errorf("failed to get secret version from DB: %w", err)
	}

	if item.State != string(types.StateEnabled) {
		return types.SecretEntry{}, false, exceptions.ErrSecretNotActive
	}

	now := time.Now().UTC()
	if item.NotBefore != "" {
		notBeforeTime, parseErr := time.Parse(time.RFC3339Nano, item.NotBefore)
		if parseErr != nil {
			return types.SecretEntry{}, false, fmt.Errorf("failed to parse NotBefore timestamp for secret %s v%d: %w", secretIdentifier.Name, targetVersion, parseErr)
		}
		if now.Before(notBeforeTime) {
			return types.SecretEntry{}, false, exceptions.ErrSecretNotActive
		}
	}
	if item.NotAfter != "" {
		notAfterTime, parseErr := time.Parse(time.RFC3339Nano, item.NotAfter)
		if parseErr != nil {
			return types.SecretEntry{}, false, fmt.Errorf("failed to parse NotAfter timestamp for secret %s v%d: %w", secretIdentifier.Name, targetVersion, parseErr)
		}
		if now.After(notAfterTime) {
			return types.SecretEntry{}, false, exceptions.ErrSecretNotActive
		}
	}

	rawSecretEntry := rawSecretEntryFromDynamoItem(*item)

	secretEntry, err := sg.Decrypt(ctx, rawSecretEntry, secretIdentifier, targetVersion)
	if err != nil {
		return types.SecretEntry{}, false, fmt.Errorf("failed to decrypt secret %s v%d: %w", secretIdentifier.Name, targetVersion, err)
	}

	return secretEntry, true, nil
}

// GetLatestActiveVersion retrieves the most recent version of a secret that is currently active.
// It queries for the latest version by version number and then checks its active status using GetActive.
//
// ctx: Context for the API operation.
// secretIdentifier: The name of the secret.
// Returns the decrypted SecretEntry, a boolean indicating if found and active, and an error.
// If no versions exist or no version is active, found will be false.
func (sg *DefaultSecretsGroup) GetLatestActiveVersion(ctx context.Context, secretIdentifier types.SecretIdentifier) (types.SecretEntry, bool, error) {
	nameAV, err := attributevalue.Marshal(secretIdentifier.Name)
	if err != nil {
		return types.SecretEntry{}, false, fmt.Errorf("failed to marshal secret name for query: %w", err)
	}

	queryInput := &ddbsvc.QueryInput{
		TableName:              aws.String(sg.tableName),
		KeyConditionExpression: aws.String("SecretName = :nameVal"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":nameVal": nameAV,
		},
		ScanIndexForward: aws.Bool(false), 
		Limit:            aws.Int32(1),
	}

	queryOutput, err := sg.dynamoClient.Query(ctx, queryInput)
	if err != nil {
		return types.SecretEntry{}, false, fmt.Errorf("DynamoDB Query failed for latest version of secret %s: %w", secretIdentifier.Name, err)
	}

	if len(queryOutput.Items) == 0 {
		return types.SecretEntry{}, false, nil 
	}

	var item dynamoSecretItem
	err = attributevalue.UnmarshalMap(queryOutput.Items[0], &item)
	if err != nil {
		return types.SecretEntry{}, false, fmt.Errorf("failed to unmarshal DynamoDB item for secret %s: %w", secretIdentifier.Name, err)
	}

	return sg.GetActive(ctx, secretIdentifier, item.Version)
}

// ListSecrets retrieves all versions of all secrets within this group as RawSecretEntry objects.
// This method performs a DynamoDB Scan operation and can be resource-intensive.
// It's recommended for administrative purposes or when all raw secret data is genuinely needed.
//
// ctx: Context for the API operation.
// Returns a slice of RawSecretEntry (containing encrypted data and metadata) or an error.
func (sg *DefaultSecretsGroup) ListSecrets(ctx context.Context) ([]types.RawSecretEntry, error) {
	var allRawSecrets []types.RawSecretEntry
	var lastEvaluatedKey map[string]ddbtypes.AttributeValue

	for {
		scanInput := &ddbsvc.ScanInput{
			TableName:         aws.String(sg.tableName),
			ExclusiveStartKey: lastEvaluatedKey,
		}

		scanOutput, err := sg.dynamoClient.Scan(ctx, scanInput)
		if err != nil {
			return nil, fmt.Errorf("DynamoDB Scan failed: %w", err)
		}

		for _, dbItem := range scanOutput.Items {
			var item dynamoSecretItem
			err = attributevalue.UnmarshalMap(dbItem, &item)
			if err != nil {
				// Log error and continue? Or return error immediately?
				// For now, skip problematic items.
				// log.Printf("Warning: failed to unmarshal item during ListSecrets: %v", err)
				continue
			}
			allRawSecrets = append(allRawSecrets, rawSecretEntryFromDynamoItem(item))
		}

		if scanOutput.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = scanOutput.LastEvaluatedKey
	}
	return allRawSecrets, nil
}

// Identifiers lists the names (identifiers) of all unique secrets stored within this group.
// It performs a DynamoDB Scan with a projection to retrieve only secret names, optimizing data transfer.
//
// ctx: Context for the API operation.
// Returns a slice of unique SecretIdentifier or an error.
func (sg *DefaultSecretsGroup) Identifiers(ctx context.Context) ([]types.SecretIdentifier, error) {
	uniqueNames := make(map[string]struct{})
	var identifiers []types.SecretIdentifier
	var lastEvaluatedKey map[string]ddbtypes.AttributeValue

	for {
		scanInput := &ddbsvc.ScanInput{
			TableName:         aws.String(sg.tableName),
			ProjectionExpression: aws.String("SecretName"),
			ExclusiveStartKey: lastEvaluatedKey,
		}
		scanOutput, err := sg.dynamoClient.Scan(ctx, scanInput)
		if err != nil {
			return nil, fmt.Errorf("DynamoDB Scan for Identifiers failed: %w", err)
		}

		for _, itemMap := range scanOutput.Items {
			if nameAttr, ok := itemMap["SecretName"]; ok {
				var secretName string
				err := attributevalue.Unmarshal(nameAttr, &secretName)
				if err == nil && secretName != "" {
					if _, exists := uniqueNames[secretName]; !exists {
						uniqueNames[secretName] = struct{}{}
						identifiers = append(identifiers, types.SecretIdentifier{Name: secretName})
					}
				}
			}
		}
		if scanOutput.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = scanOutput.LastEvaluatedKey
	}
	return identifiers, nil
}

// GetAllActiveVersions retrieves all active versions of a specific secret, decrypts them, and returns them.
//
// ctx: Context for the API operation.
// secretIdentifier: The name of the secret.
// Returns a slice of decrypted SecretEntry for all active versions, or an error.
func (sg *DefaultSecretsGroup) GetAllActiveVersions(ctx context.Context, secretIdentifier types.SecretIdentifier) ([]types.SecretEntry, error) {
	var activeEntries []types.SecretEntry
	nameAV, err := attributevalue.Marshal(secretIdentifier.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret name for query: %w", err)
	}

	queryInput := &ddbsvc.QueryInput{
		TableName:              aws.String(sg.tableName),
		KeyConditionExpression: aws.String("SecretName = :nameVal"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":nameVal": nameAV,
		},
	}
	
	var lastEvaluatedKey map[string]ddbtypes.AttributeValue
	for {
		queryInput.ExclusiveStartKey = lastEvaluatedKey
		queryOutput, err := sg.dynamoClient.Query(ctx, queryInput)
		if err != nil {
			return nil, fmt.Errorf("DynamoDB Query failed for all versions of secret %s: %w", secretIdentifier.Name, err)
		}

		for _, dbItem := range queryOutput.Items {
			var item dynamoSecretItem
			errUnmarshal := attributevalue.UnmarshalMap(dbItem, &item)
			if errUnmarshal != nil {
				// log.Printf("Warning: failed to unmarshal item during GetAllActiveVersions: %v", errUnmarshal)
				continue
			}
			
			entry, isActive, errGetActive := sg.GetActive(ctx, secretIdentifier, item.Version)
			if errGetActive != nil {
				// log.Printf("Warning: GetActive failed for %s v%d: %v", secretIdentifier.Name, item.Version, errGetActive)
				continue
			}
			if isActive {
				activeEntries = append(activeEntries, entry)
			}
		}

		if queryOutput.LastEvaluatedKey == nil {
			break
		}
		lastEvaluatedKey = queryOutput.LastEvaluatedKey
	}
	return activeEntries, nil
}

// GetLatestActiveVersionOfAllSecrets is not yet implemented.
func (sg *DefaultSecretsGroup) GetLatestActiveVersionOfAllSecrets(ctx context.Context) ([]types.SecretEntry, error) {
	return nil, exceptions.ErrNotImplemented
}

// GetAllActiveVersionsOfAll is not yet implemented.
func (sg *DefaultSecretsGroup) GetAllActiveVersionsOfAll(ctx context.Context) ([]types.SecretEntry, error) {
	return nil, exceptions.ErrNotImplemented
}

// SRN generates the Strongbox Resource Name (SRN) for a given secret identifier within this group.
// The SRN is a unique identifier for the secret.
func (sg *DefaultSecretsGroup) SRN(ctx context.Context, secretIdentifier types.SecretIdentifier) (types.SRN, error) {
	if secretIdentifier.Name == "" {
		return types.SRN{}, exceptions.ErrConfiguration 
	}
	// Example SRN format, actual format might differ based on system design.
	return types.SRN{Raw: "srn:strongbox:" + sg.Region + ":" + sg.Identifier.Name + ":secret/" + secretIdentifier.Name}, nil
}

// Close performs any necessary cleanup for the SecretsGroup. Currently a no-op.
func (sg *DefaultSecretsGroup) Close(ctx context.Context) error {
	return nil
}

// --- SimpleSecretsGroup Implementation ---

// GetStringSecret retrieves the latest active version of a secret as a string.
func (sg *DefaultSecretsGroup) GetStringSecret(ctx context.Context, secretIdentifier types.SecretIdentifier) (string, bool, error) {
	entry, found, err := sg.GetLatestActiveVersion(ctx, secretIdentifier)
	if err != nil { return "", false, err }
	if !found { return "", false, nil }
	// Optional: Could check entry.Metadata.SecretType here if it's reliably "text/plain" or similar
	return string(entry.SecretValue), true, nil
}

// GetStringSecretByName retrieves the latest active version of a secret by its name as a string.
func (sg *DefaultSecretsGroup) GetStringSecretByName(ctx context.Context, name string) (string, bool, error) {
	return sg.GetStringSecret(ctx, types.SecretIdentifier{Name: name})
}

// GetStringSecretVersion retrieves a specific active version of a secret as a string.
func (sg *DefaultSecretsGroup) GetStringSecretVersion(ctx context.Context, secretIdentifier types.SecretIdentifier, version int64) (string, bool, error) {
	entry, found, err := sg.GetActive(ctx, secretIdentifier, version)
	if err != nil { return "", false, err }
	if !found { return "", false, nil }
	return string(entry.SecretValue), true, nil
}

// GetStringSecretByNameVersion retrieves a specific active version of a secret by name and version as a string.
func (sg *DefaultSecretsGroup) GetStringSecretByNameVersion(ctx context.Context, name string, version int64) (string, bool, error) {
	return sg.GetStringSecretVersion(ctx, types.SecretIdentifier{Name: name}, version)
}

// GetAllStringSecrets is not yet implemented.
func (sg *DefaultSecretsGroup) GetAllStringSecrets(ctx context.Context) ([]types.StringSecretEntry, error) {
	return nil, exceptions.ErrNotImplemented 
}

// GetBinarySecret retrieves the latest active version of a secret as a byte slice.
func (sg *DefaultSecretsGroup) GetBinarySecret(ctx context.Context, secretIdentifier types.SecretIdentifier) ([]byte, bool, error) {
	entry, found, err := sg.GetLatestActiveVersion(ctx, secretIdentifier)
	if err != nil { return nil, false, err }
	if !found { return nil, false, nil }
	return entry.SecretValue, true, nil
}

// GetBinarySecretByName retrieves the latest active version of a secret by its name as a byte slice.
func (sg *DefaultSecretsGroup) GetBinarySecretByName(ctx context.Context, name string) ([]byte, bool, error) {
	return sg.GetBinarySecret(ctx, types.SecretIdentifier{Name: name})
}

// GetBinarySecretVersion retrieves a specific active version of a secret as a byte slice.
func (sg *DefaultSecretsGroup) GetBinarySecretVersion(ctx context.Context, secretIdentifier types.SecretIdentifier, version int64) ([]byte, bool, error) {
	entry, found, err := sg.GetActive(ctx, secretIdentifier, version)
	if err != nil { return nil, false, err }
	if !found { return nil, false, nil }
	return entry.SecretValue, true, nil
}

// GetBinarySecretByNameVersion retrieves a specific active version of a secret by name and version as a byte slice.
func (sg *DefaultSecretsGroup) GetBinarySecretByNameVersion(ctx context.Context, name string, version int64) ([]byte, bool, error) {
	return sg.GetBinarySecretVersion(ctx, types.SecretIdentifier{Name: name}, version)
}

// GetAllBinarySecrets is not yet implemented.
func (sg *DefaultSecretsGroup) GetAllBinarySecrets(ctx context.Context) ([]types.ByteSecretEntry, error) {
	return nil, exceptions.ErrNotImplemented 
}
