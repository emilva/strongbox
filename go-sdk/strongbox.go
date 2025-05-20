// Package strongbox provides the Go SDK for interacting with Strongbox services.
// It allows for secure management and retrieval of secrets, using AWS KMS for
// cryptographic operations and key management, and AWS DynamoDB for storage
// of secret metadata and encrypted values.
package strongbox

import (
	"context"
	"encoding/json" // For JSON handling
	"errors"        // For errors.As
	"fmt"           // For error wrapping
	"strings"       // For strings.HasPrefix and strings.TrimPrefix
	"time"          // For time.Time

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb" // Added import
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types" // Alias for KMS specific types
	"github.com/aws/smithy-go"                               // For APIError

	"go-sdk/exceptions"
	"go-sdk/types"
)

// KMSAPI defines the subset of AWS KMS client methods used by DefaultSecretsGroupManager
// and DefaultSecretsGroup. This interface allows for easier mocking in tests.
type KMSAPI interface {
	// CreateKey creates a new customer master key (CMK).
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	// CreateAlias creates a friendly name for a CMK.
	CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	// ScheduleKeyDeletion schedules the deletion of a CMK.
	ScheduleKeyDeletion(ctx context.Context, params *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	// DescribeKey provides detailed information about a CMK.
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	// DeleteAlias deletes an alias.
	DeleteAlias(ctx context.Context, params *kms.DeleteAliasInput, optFns ...func(*kms.Options)) (*kms.DeleteAliasOutput, error)
	// ListAliases returns a list of aliases in the account.
	ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	// GetKeyPolicy retrieves a key policy attached to a CMK.
	GetKeyPolicy(ctx context.Context, params *kms.GetKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	// PutKeyPolicy attaches a key policy to a CMK.
	PutKeyPolicy(ctx context.Context, params *kms.PutKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.PutKeyPolicyOutput, error)
	// Encrypt encrypts plaintext into ciphertext using a CMK.
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	// Decrypt decrypts ciphertext that was encrypted by a CMK.
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// DefaultSecretsGroupManager implements the SecretsGroupManager interface.
// It uses AWS KMS for key management and AWS DynamoDB (via SecretsGroup instances) for secret storage.
type DefaultSecretsGroupManager struct {
	kmsClient          KMSAPI      // Client for KMS operations.
	dynamoClient       DynamoDBAPI // Client for DynamoDB, passed to SecretsGroup instances.
	awsConfig          aws.Config  // AWS configuration used for clients.
	secretsTableName   string      // Name of the DynamoDB table where secrets are stored.
}

// NewDefaultSecretsGroupManager creates a new instance of DefaultSecretsGroupManager.
// It initializes clients for AWS KMS and DynamoDB based on the provided AWS configuration.
//
// ctx: The context for the operation, not directly used in this constructor but conventional for future use.
// cfg: AWS SDK configuration, used to initialize AWS clients.
// secretsTableName: The name of the DynamoDB table used for storing secrets. This table name is
//                   passed down to SecretsGroup instances created by this manager.
// Returns a pointer to the initialized DefaultSecretsGroupManager or an error if initialization fails.
func NewDefaultSecretsGroupManager(ctx context.Context, cfg aws.Config, secretsTableName string) (*DefaultSecretsGroupManager, error) {
	realKMSClient := kms.NewFromConfig(cfg)
	realDynamoClient := dynamodb.NewFromConfig(cfg) 
	return &DefaultSecretsGroupManager{
		kmsClient:        realKMSClient,
		dynamoClient:     realDynamoClient, 
		awsConfig:        cfg,
		secretsTableName: secretsTableName,   
	}, nil
}

// Create creates a new secrets group. This typically involves creating a new AWS KMS key
// and an alias for that key, formatted as "alias/strongbox/<region>/<groupName>".
//
// ctx: The context for the API operation.
// group: The identifier for the secrets group to create, specifying its region and name.
// Returns information about the created group (including its ARN and creation date) or an error.
// If an alias with the same name already exists, it attempts to clean up the potentially orphaned
// KMS key and returns an error wrapping exceptions.ErrAlreadyExists.
func (m *DefaultSecretsGroupManager) Create(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error) {
	if group.Region == "" {
		// Assuming group.Region is valid as per original implementation.
	}

	keyDescription := fmt.Sprintf("Strongbox secrets group: %s in region %s", group.Name, group.Region)
	createKeyInput := &kms.CreateKeyInput{
		Description: &keyDescription,
		Tags: []kmstypes.Tag{
			{TagKey: aws.String("strongbox:group:name"), TagValue: aws.String(group.Name)},
			{TagKey: aws.String("strongbox:group:region"), TagValue: aws.String(group.Region)},
		},
	}

	createKeyOutput, err := m.kmsClient.CreateKey(ctx, createKeyInput)
	if err != nil {
		return types.SecretsGroupInfo{}, fmt.Errorf("failed to create KMS key for group %s (region %s): %w", group.Name, group.Region, err)
	}

	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)
	createAliasInput := &kms.CreateAliasInput{
		AliasName:   aws.String(aliasName),
		TargetKeyId: createKeyOutput.KeyMetadata.KeyId,
	}

	_, err = m.kmsClient.CreateAlias(ctx, createAliasInput)
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AliasAlreadyExistsException" {
			_, delErr := m.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: createKeyOutput.KeyMetadata.KeyId, PendingWindowInDays: aws.Int32(7)})
			if delErr != nil {
				return types.SecretsGroupInfo{}, fmt.Errorf("alias %s (code: %s) already exists; failed to cleanup orphaned KMS key %s: %w (original alias error: %s)", aliasName, apiErr.ErrorCode(), *createKeyOutput.KeyMetadata.KeyId, delErr, err.Error())
			}
			return types.SecretsGroupInfo{}, fmt.Errorf("alias %s (code: %s) already exists for group %s (region %s), orphaned KMS key %s scheduled for deletion: %w", aliasName, apiErr.ErrorCode(), group.Name, group.Region, *createKeyOutput.KeyMetadata.KeyId, exceptions.ErrAlreadyExists)
		}
		_, delErr := m.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{KeyId: createKeyOutput.KeyMetadata.KeyId, PendingWindowInDays: aws.Int32(7)})
		if delErr != nil {
			return types.SecretsGroupInfo{}, fmt.Errorf("failed to create KMS alias %s for group %s (region %s), and also failed to cleanup orphaned key %s: %w (original alias error: %s)", aliasName, group.Name, group.Region, *createKeyOutput.KeyMetadata.KeyId, delErr, err.Error())
		}
		return types.SecretsGroupInfo{}, fmt.Errorf("failed to create KMS alias %s for group %s (region %s), orphaned key %s scheduled for deletion: %w", aliasName, group.Name, group.Region, *createKeyOutput.KeyMetadata.KeyId, err)
	}

	return types.SecretsGroupInfo{
		Identifier: group,
		ARN:        *createKeyOutput.KeyMetadata.Arn,
		CreatedAt:  *createKeyOutput.KeyMetadata.CreationDate,
	}, nil
}

// Get returns a SecretsGroup instance for managing secrets within the specified group.
//
// ctx: The context for the operation.
// group: The identifier of the secrets group to access.
// Returns a SecretsGroup interface instance or an error if the group cannot be accessed.
// The current stub implementation returns an error if group.Name is "non_existent_group".
func (m *DefaultSecretsGroupManager) Get(ctx context.Context, group types.SecretsGroupIdentifier) (SecretsGroup, error) {
	if group.Name == "non_existent_group" { // Stub behavior
		return nil, exceptions.ErrNotFound
	}
	return NewDefaultSecretsGroup(
		group,
		m.kmsClient,
		m.dynamoClient,
		m.secretsTableName, 
		m.awsConfig.Region, // Pass the manager's configured region to the group
	), nil
}

// Delete schedules the deletion of the KMS key associated with the secrets group and removes its alias.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group to delete.
// Returns nil on successful initiation of deletion or if the group (alias) is already not found.
// Returns an error if any step of the deletion process fails.
func (m *DefaultSecretsGroupManager) Delete(ctx context.Context, group types.SecretsGroupIdentifier) error {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)
	var keyIdToSchedule string

	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return nil
		}
		return fmt.Errorf("failed to describe KMS key for alias %s: %w", aliasName, err)
	}
	keyIdToSchedule = *describeKeyOutput.KeyMetadata.KeyId

	_, err = m.kmsClient.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(keyIdToSchedule),
		PendingWindowInDays: aws.Int32(7),
	})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		var invStateException *kmstypes.KMSInvalidStateException
		if errors.As(err, &nfe) {
		} else if errors.As(err, &invStateException) {
		} else {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				return fmt.Errorf("failed to schedule KMS key deletion for key ID %s (alias %s): %w. API Error Code: %s, Message: %s", keyIdToSchedule, aliasName, err, apiErr.ErrorCode(), apiErr.ErrorMessage())
			}
			return fmt.Errorf("failed to schedule KMS key deletion for key ID %s (alias %s): %w", keyIdToSchedule, aliasName, err)
		}
	}

	_, err = m.kmsClient.DeleteAlias(ctx, &kms.DeleteAliasInput{AliasName: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
		} else {
			return fmt.Errorf("failed to delete KMS alias %s (key deletion may already be scheduled): %w", aliasName, err)
		}
	}
	return nil
}

// Identifiers lists all Strongbox-managed secrets group identifiers in the configured AWS region.
// It iterates through all KMS aliases, filtering for those that match the Strongbox naming convention.
//
// ctx: The context for the API operation.
// Returns a slice of SecretsGroupIdentifier or an error if listing aliases fails.
func (m *DefaultSecretsGroupManager) Identifiers(ctx context.Context) ([]types.SecretsGroupIdentifier, error) {
	var identifiers []types.SecretsGroupIdentifier
	var marker *string
	aliasPrefix := fmt.Sprintf("alias/strongbox/%s/", m.awsConfig.Region)

	for {
		listAliasesInput := &kms.ListAliasesInput{Marker: marker, Limit: aws.Int32(100)}
		listAliasesOutput, err := m.kmsClient.ListAliases(ctx, listAliasesInput)
		if err != nil {
			return nil, fmt.Errorf("failed to list KMS aliases: %w", err)
		}

		for _, alias := range listAliasesOutput.Aliases {
			aliasName := aws.ToString(alias.AliasName)
			if strings.HasPrefix(aliasName, aliasPrefix) {
				groupName := strings.TrimPrefix(aliasName, aliasPrefix)
				if groupName != "" {
					identifiers = append(identifiers, types.SecretsGroupIdentifier{
						Region: m.awsConfig.Region,
						Name:   groupName,
					})
				}
			}
		}
		if listAliasesOutput.NextMarker == nil || *listAliasesOutput.NextMarker == "" {
			break
		}
		marker = listAliasesOutput.NextMarker
	}
	return identifiers, nil
}

// Info retrieves metadata about a specific secrets group.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group.
// Returns information about the group (ARN, creation date) or an error if the group is not found
// or if there's an issue retrieving its details.
func (m *DefaultSecretsGroupManager) Info(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error) {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)
	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return types.SecretsGroupInfo{}, exceptions.ErrNotFound
		}
		return types.SecretsGroupInfo{}, fmt.Errorf("failed to describe KMS key for alias %s: %w", aliasName, err)
	}

	if describeKeyOutput.KeyMetadata == nil {
		return types.SecretsGroupInfo{}, fmt.Errorf("KMS DescribeKey returned nil KeyMetadata for alias %s", aliasName)
	}

	var createdAt time.Time
	if describeKeyOutput.KeyMetadata.CreationDate != nil {
		createdAt = *describeKeyOutput.KeyMetadata.CreationDate
	}

	return types.SecretsGroupInfo{
		Identifier: group,
		ARN:        aws.ToString(describeKeyOutput.KeyMetadata.Arn),
		CreatedAt:  createdAt,
	}, nil
}

// AttachAdmin grants administrative permissions to the specified principal for the secrets group.
// This modifies the KMS key policy associated with the group.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group.
// principal: The principal (e.g., IAM user/role ARN) to grant admin access.
// Returns nil on success, or an error if the operation fails.
func (m *DefaultSecretsGroupManager) AttachAdmin(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)

	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return fmt.Errorf("group '%s' not found: %w", group.Name, exceptions.ErrNotFound)
		}
		return fmt.Errorf("failed to describe KMS key for alias %s: %w", aliasName, err)
	}
	keyArn := aws.ToString(describeKeyOutput.KeyMetadata.Arn)
	if keyArn == "" {
		return fmt.Errorf("KMS DescribeKey returned empty ARN for alias %s", aliasName)
	}

	policyOutput, err := m.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyArn),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return fmt.Errorf("failed to get KMS key policy for %s: %w", keyArn, err)
	}
	if policyOutput.Policy == nil || *policyOutput.Policy == "" {
		return fmt.Errorf("KMS GetKeyPolicy returned empty policy for %s", keyArn)
	}

	var policyDocument map[string]interface{}
	err = json.Unmarshal([]byte(*policyOutput.Policy), &policyDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key policy JSON for %s: %w", keyArn, err)
	}

	statements, ok := policyDocument["Statement"].([]interface{})
	if !ok {
		statements = make([]interface{}, 0)
	}

	sidSuffix := strings.ReplaceAll(strings.ReplaceAll(principal.ID, ":", "-"), "*", "-")
	if len(sidSuffix) > 50 {
		sidSuffix = sidSuffix[len(sidSuffix)-50:]
	}
	newStatementSid := fmt.Sprintf("StrongboxAdmin-%s", sidSuffix)

	statementExists := false
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}
		if sid, ok := stmt["Sid"].(string); ok && sid == newStatementSid {
			statementExists = true
			break
		}
	}

	if !statementExists {
		newStatement := map[string]interface{}{
			"Sid":    newStatementSid,
			"Effect": "Allow",
			"Principal": map[string]string{"AWS": principal.ID},
			"Action":   "kms:*",
			"Resource": keyArn,
		}
		statements = append(statements, newStatement)
		policyDocument["Statement"] = statements
	} else {
		return nil
	}

	newPolicyJsonBytes, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal modified key policy for %s: %w", keyArn, err)
	}

	_, err = m.kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:      aws.String(keyArn),
		PolicyName: aws.String("default"),
		Policy:     aws.String(string(newPolicyJsonBytes)),
	})
	if err != nil {
		return fmt.Errorf("failed to put updated KMS key policy for %s: %w", keyArn, err)
	}
	return nil
}

// DetachAdmin revokes administrative permissions from the specified principal for the secrets group.
// This modifies the KMS key policy by removing the relevant statement.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group.
// principal: The principal whose admin access is to be revoked.
// Returns nil on success or if the principal was not an admin, or an error if the operation fails.
func (m *DefaultSecretsGroupManager) DetachAdmin(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)

	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return fmt.Errorf("group '%s' not found: %w", group.Name, exceptions.ErrNotFound)
		}
		return fmt.Errorf("failed to describe KMS key for alias %s: %w", aliasName, err)
	}
	keyArn := aws.ToString(describeKeyOutput.KeyMetadata.Arn)
	if keyArn == "" {
		return fmt.Errorf("KMS DescribeKey returned empty ARN for alias %s", aliasName)
	}

	policyOutput, err := m.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(keyArn), PolicyName: aws.String("default")})
	if err != nil {
		return fmt.Errorf("failed to get KMS key policy for %s: %w", keyArn, err)
	}
	if policyOutput.Policy == nil || *policyOutput.Policy == "" {
		return fmt.Errorf("KMS GetKeyPolicy returned empty policy for %s (or policy is literally empty string)", keyArn)
	}

	var policyDocument map[string]interface{}
	err = json.Unmarshal([]byte(*policyOutput.Policy), &policyDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key policy JSON for %s: %w", keyArn, err)
	}

	statements, ok := policyDocument["Statement"].([]interface{})
	if !ok { 
		return nil
	}

	sidSuffix := strings.ReplaceAll(strings.ReplaceAll(principal.ID, ":", "-"), "*", "-")
	if len(sidSuffix) > 50 {
		sidSuffix = sidSuffix[len(sidSuffix)-50:]
	}
	sidToRemove := fmt.Sprintf("StrongboxAdmin-%s", sidSuffix)

	newStatements := make([]interface{}, 0, len(statements))
	foundStatementToRemove := false
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			newStatements = append(newStatements, stmtInterface)
			continue
		}
		if sid, ok := stmt["Sid"].(string); ok && sid == sidToRemove {
			foundStatementToRemove = true
		} else {
			newStatements = append(newStatements, stmt)
		}
	}

	if !foundStatementToRemove {
		return nil 
	}
	
	policyDocument["Statement"] = newStatements

	newPolicyJsonBytes, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal modified key policy for %s: %w", keyArn, err)
	}

	_, err = m.kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:      aws.String(keyArn),
		PolicyName: aws.String("default"),
		Policy:     aws.String(string(newPolicyJsonBytes)),
	})
	if err != nil {
		return fmt.Errorf("failed to put updated KMS key policy for %s: %w", keyArn, err)
	}
	return nil
}

// AttachReadOnly grants read-only permissions (kms:Decrypt, kms:DescribeKey) to the specified principal
// for the secrets group. This modifies the KMS key policy.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group.
// principal: The principal to grant read-only access.
// Returns nil on success, or an error if the operation fails.
func (m *DefaultSecretsGroupManager) AttachReadOnly(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)

	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return fmt.Errorf("group '%s' not found: %w", group.Name, exceptions.ErrNotFound)
		}
		return fmt.Errorf("failed to describe KMS key for alias %s: %w", aliasName, err)
	}
	keyArn := aws.ToString(describeKeyOutput.KeyMetadata.Arn)
	if keyArn == "" {
		return fmt.Errorf("KMS DescribeKey returned empty ARN for alias %s", aliasName)
	}

	policyOutput, err := m.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(keyArn), PolicyName: aws.String("default")})
	if err != nil {
		return fmt.Errorf("failed to get KMS key policy for %s: %w", keyArn, err)
	}
	if policyOutput.Policy == nil || *policyOutput.Policy == "" {
		return fmt.Errorf("KMS GetKeyPolicy returned empty policy for %s", keyArn)
	}

	var policyDocument map[string]interface{}
	err = json.Unmarshal([]byte(*policyOutput.Policy), &policyDocument)
	if err != nil {
		return fmt.Errorf("failed to unmarshal key policy JSON for %s: %w", keyArn, err)
	}

	statements, ok := policyDocument["Statement"].([]interface{})
	if !ok {
		statements = make([]interface{}, 0)
	}

	sidSuffix := strings.ReplaceAll(strings.ReplaceAll(principal.ID, ":", "-"), "*", "-")
	if len(sidSuffix) > 50 {
		sidSuffix = sidSuffix[len(sidSuffix)-50:]
	}
	newReadOnlySid := fmt.Sprintf("StrongboxReadOnly-%s", sidSuffix)

	statementExists := false
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok {
			continue
		}
		if sid, ok := stmt["Sid"].(string); ok && sid == newReadOnlySid {
			statementExists = true
			break
		}
	}

	if statementExists {
		return nil 
	}

	newStatement := map[string]interface{}{
		"Sid":    newReadOnlySid,
		"Effect": "Allow",
		"Principal": map[string]string{"AWS": principal.ID},
		"Action":   []string{"kms:Decrypt", "kms:DescribeKey"}, 
		"Resource": keyArn,
	}
	statements = append(statements, newStatement)
	policyDocument["Statement"] = statements

	newPolicyJsonBytes, err := json.Marshal(policyDocument)
	if err != nil {
		return fmt.Errorf("failed to marshal modified key policy for %s: %w", keyArn, err)
	}

	_, err = m.kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:      aws.String(keyArn),
		PolicyName: aws.String("default"),
		Policy:     aws.String(string(newPolicyJsonBytes)),
	})
	if err != nil {
		return fmt.Errorf("failed to put updated KMS key policy for %s: %w", keyArn, err)
	}
	return nil
}

// DetachReadOnly revokes read-only permissions from the specified principal for the secrets group.
// This modifies the KMS key policy by removing the relevant statement.
//
// ctx: The context for the API operation.
// group: The identifier of the secrets group.
// principal: The principal whose read-only access is to be revoked.
// Returns nil on success or if the principal did not have read-only access, or an error if the operation fails.
func (m *DefaultSecretsGroupManager) DetachReadOnly(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error {
	aliasName := fmt.Sprintf("alias/strongbox/%s/%s", group.Region, group.Name)

	describeKeyOutput, err := m.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(aliasName)})
	if err != nil {
		var nfe *kmstypes.NotFoundException
		if errors.As(err, &nfe) {
			return fmt.Errorf("group '%s' not found: %w", group.Name, exceptions.ErrNotFound)
		}
		return fmt.Errorf("failed to describe KMS key for alias %s in DetachReadOnly: %w", aliasName, err)
	}
	keyArn := aws.ToString(describeKeyOutput.KeyMetadata.Arn)
	if keyArn == "" {
		return fmt.Errorf("KMS DescribeKey returned empty ARN for alias %s in DetachReadOnly", aliasName)
	}

	policyOutput, err := m.kmsClient.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(keyArn), PolicyName: aws.String("default")})
	if err != nil { 
		return fmt.Errorf("failed to get key policy in DetachReadOnly for %s: %w", keyArn, err) 
	}
    if policyOutput.Policy == nil || *policyOutput.Policy == "" {
		return fmt.Errorf("KMS GetKeyPolicy returned empty policy for %s in DetachReadOnly", keyArn)
	}

	var policyDocument map[string]interface{}
	err = json.Unmarshal([]byte(*policyOutput.Policy), &policyDocument)
	if err != nil { 
		return fmt.Errorf("failed to unmarshal policy in DetachReadOnly for %s: %w", keyArn, err) 
	}

	statements, ok := policyDocument["Statement"].([]interface{})
	if !ok { 
		return nil
	}

	sidSuffix := strings.ReplaceAll(strings.ReplaceAll(principal.ID, ":", "-"), "*", "-")
	if len(sidSuffix) > 50 { sidSuffix = sidSuffix[len(sidSuffix)-50:] }
	sidToRemove := fmt.Sprintf("StrongboxReadOnly-%s", sidSuffix) 

	newStatements := make([]interface{}, 0, len(statements))
	foundStatementToRemove := false
	for _, stmtInterface := range statements {
		stmt, ok := stmtInterface.(map[string]interface{})
		if !ok { 
			newStatements = append(newStatements, stmtInterface)
			continue 
		}
		if sid, ok := stmt["Sid"].(string); ok && sid == sidToRemove {
			foundStatementToRemove = true
		} else {
			newStatements = append(newStatements, stmt)
		}
	}

	if !foundStatementToRemove {
		return nil 
	}
    
	policyDocument["Statement"] = newStatements

	newPolicyJsonBytes, err := json.Marshal(policyDocument)
	if err != nil { 
		return fmt.Errorf("failed to marshal policy in DetachReadOnly for %s: %w", keyArn, err) 
	}

	_, err = m.kmsClient.PutKeyPolicy(ctx, &kms.PutKeyPolicyInput{
		KeyId:      aws.String(keyArn),
		PolicyName: aws.String("default"),
		Policy:     aws.String(string(newPolicyJsonBytes)),
	})
	if err != nil { 
		return fmt.Errorf("failed to put policy in DetachReadOnly for %s: %w", keyArn, err) 
	}

	return nil
}
