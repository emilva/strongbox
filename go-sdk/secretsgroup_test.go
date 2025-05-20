package strongbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddbsvc "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	kmssvc "github.com/aws/aws-sdk-go-v2/service/kms"
	// kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types" // Not directly used for errors here

	"go-sdk/exceptions"
	"go-sdk/types"
)

// --- Start of Mocks ---
// Minimal KMSAPI mock for Create tests
type mockSGKMSClient struct {
	EncryptFunc func(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error)
	// DecryptFunc needed if other methods being tested in this file use it. For Create, only Encrypt.
	// To satisfy KMSAPI fully, other methods would need to be here.
	// For this specific test (TestSecretsGroup_Create), only Encrypt is vital.
	// The other methods are added to satisfy the interface if it's checked strictly.
	CreateKeyFunc           func(ctx context.Context, params *kmssvc.CreateKeyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.CreateKeyOutput, error)
	CreateAliasFunc         func(ctx context.Context, params *kmssvc.CreateAliasInput, optFns ...func(*kmssvc.Options)) (*kmssvc.CreateAliasOutput, error)
	ScheduleKeyDeletionFunc func(ctx context.Context, params *kmssvc.ScheduleKeyDeletionInput, optFns ...func(*kmssvc.Options)) (*kmssvc.ScheduleKeyDeletionOutput, error)
	DescribeKeyFunc         func(ctx context.Context, params *kmssvc.DescribeKeyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DescribeKeyOutput, error)
	DeleteAliasFunc         func(ctx context.Context, params *kmssvc.DeleteAliasInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DeleteAliasOutput, error)
	ListAliasesFunc         func(ctx context.Context, params *kmssvc.ListAliasesInput, optFns ...func(*kmssvc.Options)) (*kmssvc.ListAliasesOutput, error)
	GetKeyPolicyFunc        func(ctx context.Context, params *kmssvc.GetKeyPolicyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.GetKeyPolicyOutput, error)
	PutKeyPolicyFunc        func(ctx context.Context, params *kmssvc.PutKeyPolicyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.PutKeyPolicyOutput, error)
	DecryptFunc             func(ctx context.Context, params *kmssvc.DecryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DecryptOutput, error)
}

func (m *mockSGKMSClient) Encrypt(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("mockSGKMSClient.EncryptFunc not implemented")
}
func (m *mockSGKMSClient) CreateKey(ctx context.Context, params *kmssvc.CreateKeyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.CreateKeyOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) CreateAlias(ctx context.Context, params *kmssvc.CreateAliasInput, optFns ...func(*kmssvc.Options)) (*kmssvc.CreateAliasOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) ScheduleKeyDeletion(ctx context.Context, params *kmssvc.ScheduleKeyDeletionInput, optFns ...func(*kmssvc.Options)) (*kmssvc.ScheduleKeyDeletionOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) DescribeKey(ctx context.Context, params *kmssvc.DescribeKeyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DescribeKeyOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) DeleteAlias(ctx context.Context, params *kmssvc.DeleteAliasInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DeleteAliasOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) ListAliases(ctx context.Context, params *kmssvc.ListAliasesInput, optFns ...func(*kmssvc.Options)) (*kmssvc.ListAliasesOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) GetKeyPolicy(ctx context.Context, params *kmssvc.GetKeyPolicyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.GetKeyPolicyOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) PutKeyPolicy(ctx context.Context, params *kmssvc.PutKeyPolicyInput, optFns ...func(*kmssvc.Options)) (*kmssvc.PutKeyPolicyOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGKMSClient) Decrypt(ctx context.Context, params *kmssvc.DecryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.DecryptOutput, error) {
	return nil, fmt.Errorf("not implemented")
}

var _ KMSAPI = (*mockSGKMSClient)(nil) // Compile-time check

// Minimal DynamoDBAPI mock for Create tests
type mockSGDynamoDBClient struct {
	PutItemFunc func(ctx context.Context, params *ddbsvc.PutItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.PutItemOutput, error)
	// For this specific test (TestSecretsGroup_Create), only PutItem is vital.
	// Other methods added to satisfy DynamoDBAPI fully.
	GetItemFunc    func(ctx context.Context, params *ddbsvc.GetItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.GetItemOutput, error)
	QueryFunc      func(ctx context.Context, params *ddbsvc.QueryInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.QueryOutput, error)
	UpdateItemFunc func(ctx context.Context, params *ddbsvc.UpdateItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.UpdateItemOutput, error)
	DeleteItemFunc func(ctx context.Context, params *ddbsvc.DeleteItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.DeleteItemOutput, error)
	ScanFunc       func(ctx context.Context, params *ddbsvc.ScanInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.ScanOutput, error)
}

func (m *mockSGDynamoDBClient) PutItem(ctx context.Context, params *ddbsvc.PutItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.PutItemOutput, error) {
	if m.PutItemFunc != nil {
		return m.PutItemFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("mockSGDynamoDBClient.PutItemFunc not implemented")
}
func (m *mockSGDynamoDBClient) GetItem(ctx context.Context, params *ddbsvc.GetItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.GetItemOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGDynamoDBClient) Query(ctx context.Context, params *ddbsvc.QueryInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.QueryOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGDynamoDBClient) UpdateItem(ctx context.Context, params *ddbsvc.UpdateItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.UpdateItemOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGDynamoDBClient) DeleteItem(ctx context.Context, params *ddbsvc.DeleteItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.DeleteItemOutput, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *mockSGDynamoDBClient) Scan(ctx context.Context, params *ddbsvc.ScanInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.ScanOutput, error) {
	return nil, fmt.Errorf("not implemented")
}

var _ DynamoDBAPI = (*mockSGDynamoDBClient)(nil) // Compile-time check

// Local copy of dynamoSecretItem for unmarshalling in tests.
// This avoids needing to export dynamoSecretItem from the main package.
type testDynamoSecretItem struct {
	SecretName               string            `dynamodbav:"SecretName"`
	Version                  int64             `dynamodbav:"Version"`
	EncryptedValue           []byte            `dynamodbav:"EncryptedValue"`
	SecretType               string            `dynamodbav:"SecretType"`
	Comment                  string            `dynamodbav:"Comment,omitempty"`
	NotBefore                string            `dynamodbav:"NotBefore,omitempty"`
	NotAfter                 string            `dynamodbav:"NotAfter,omitempty"`
	State                    string            `dynamodbav:"State"`
	CreatedAt                string            `dynamodbav:"CreatedAt"`
	LastUpdatedAt            string            `dynamodbav:"LastUpdatedAt"`
	KMSEncryptionContextJSON string            `dynamodbav:"KMSEncryptionContextJSON"`
	UserData                 map[string]string `dynamodbav:"UserData,omitempty"`
}

// --- End of Mocks ---

func TestSecretsGroup_Create(t *testing.T) {
	ctx := context.Background()
	mockKms := &mockSGKMSClient{}
	mockDdb := &mockSGDynamoDBClient{}
	groupRegion := "us-test-1"
	groupName := "test-secrets-group"
	tableName := "strongbox-secrets-test"

	// Since KMSAPI and DynamoDBAPI are defined in package strongbox,
	// and this test file is also package strongbox, we can assign these mocks directly.
	sg := NewDefaultSecretsGroup(
		types.SecretsGroupIdentifier{Region: groupRegion, Name: groupName},
		mockKms,
		mockDdb,
		tableName,
		groupRegion,
	)

	secretName := "MyTestSecret"
	secretValue := []byte("supersecretdata")

	now := time.Now().UTC() // For checking timestamps consistently

	newEntryBase := types.NewSecretEntry{
		Identifier: types.SecretIdentifier{Name: secretName},
		Value:      secretValue,
		SecretType: "text/plain",
		Comment:    "Test comment",
		NotBefore:  aws.Time(now.Add(-1 * time.Hour)),
		NotAfter:   aws.Time(now.Add(24 * time.Hour)),
		UserData:   map[string]string{"customKey": "customValue"},
	}

	t.Run("Success", func(t *testing.T) {
		newEntry := newEntryBase // Use a copy for each test case
		expectedCiphertext := []byte("encrypted-data-for-success")

		mockKms.EncryptFunc = func(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error) {
			if params.KeyId == nil || *params.KeyId != fmt.Sprintf("alias/strongbox/%s/%s", groupRegion, groupName) {
				return nil, fmt.Errorf("unexpected KMS KeyId: %v, want %s", params.KeyId, fmt.Sprintf("alias/strongbox/%s/%s", groupRegion, groupName))
			}
			expectedEC := map[string]string{
				"StrongboxSecretName": secretName, "StrongboxGroupName": groupName, "StrongboxRegion": groupRegion, "StrongboxVersion": "1",
			}
			if len(params.EncryptionContext) != len(expectedEC) {
				return nil, fmt.Errorf("bad ec len, got %d, want %d", len(params.EncryptionContext), len(expectedEC))
			}
			for k, v := range expectedEC {
				if params.EncryptionContext[k] != v {
					return nil, fmt.Errorf("bad ec value for key %s: got '%s', want '%s'", k, params.EncryptionContext[k], v)
				}
			}
			return &kmssvc.EncryptOutput{CiphertextBlob: expectedCiphertext}, nil
		}

		mockDdb.PutItemFunc = func(ctx context.Context, params *ddbsvc.PutItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.PutItemOutput, error) {
			if params.TableName == nil || *params.TableName != tableName {
				return nil, fmt.Errorf("unexpected table name: %v", params.TableName)
			}
			if params.ConditionExpression == nil || *params.ConditionExpression != "attribute_not_exists(SecretName) AND attribute_not_exists(Version)" {
				return nil, fmt.Errorf("unexpected condition expression: %v", *params.ConditionExpression)
			}

			var item testDynamoSecretItem
			err := attributevalue.UnmarshalMap(params.Item, &item)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal item in test: %w", err)
			}
			if item.SecretName != secretName {
				t.Errorf("bad secret name in DDB item: got %s, want %s", item.SecretName, secretName)
			}
			if item.Version != 1 {
				t.Errorf("bad version in DDB item: got %d, want 1", item.Version)
			}
			if string(item.EncryptedValue) != string(expectedCiphertext) {
				t.Errorf("EncryptedValue mismatch in DDB item")
			}
			if item.SecretType != newEntry.SecretType {
				t.Errorf("SecretType mismatch in DDB item")
			}
			if item.Comment != newEntry.Comment {
				t.Errorf("Comment mismatch in DDB item")
			}
			if item.State != string(types.StateEnabled) {
				t.Errorf("State mismatch in DDB item, got %s", item.State)
			}
			if item.UserData["customKey"] != "customValue" {
				t.Errorf("UserData mismatch in DDB item")
			}

			// Check timestamps (approximate for CreatedAt/LastUpdatedAt)
			// NotBefore/NotAfter should be exact if set
			if item.NotBefore != newEntry.NotBefore.Format(time.RFC3339Nano) {
				t.Errorf("NotBefore mismatch in DDB item")
			}
			if item.NotAfter != newEntry.NotAfter.Format(time.RFC3339Nano) {
				t.Errorf("NotAfter mismatch in DDB item")
			}

			return &ddbsvc.PutItemOutput{}, nil
		}

		rawEntry, err := sg.Create(ctx, newEntry)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		if rawEntry.Identifier.Name != secretName {
			t.Errorf("Expected secret name %s, got %s", secretName, rawEntry.Identifier.Name)
		}
		if rawEntry.Version != 1 {
			t.Errorf("Expected version 1, got %d", rawEntry.Version)
		}
		if string(rawEntry.EncryptedData) != string(expectedCiphertext) {
			t.Errorf("EncryptedData mismatch in RawSecretEntry")
		}

		var ecMap map[string]string
		if err := json.Unmarshal([]byte(rawEntry.Metadata.KMSEncryptionContextJSON), &ecMap); err != nil {
			t.Fatalf("Failed to unmarshal KMSEncryptionContextJSON: %v", err)
		}
		if ecMap["StrongboxVersion"] != "1" {
			t.Errorf("Wrong version in EC JSON: got %s", ecMap["StrongboxVersion"])
		}
		if ecMap["StrongboxSecretName"] != secretName {
			t.Errorf("Wrong secret name in EC JSON")
		}

		if rawEntry.Metadata.Comment != newEntry.Comment {
			t.Errorf("Metadata.Comment mismatch")
		}
		if rawEntry.Metadata.State != string(types.StateEnabled) {
			t.Errorf("Metadata.State mismatch")
		}
		if rawEntry.Metadata.UserData["customKey"] != "customValue" {
			t.Errorf("Metadata.UserData mismatch")
		}

		// Time comparisons
		if rawEntry.Metadata.CreatedAt.IsZero() {
			t.Errorf("Metadata.CreatedAt is zero")
		}
		if rawEntry.Metadata.LastUpdatedAt.IsZero() {
			t.Errorf("Metadata.LastUpdatedAt is zero")
		}
		if !rawEntry.Metadata.NotBefore.Equal(*newEntry.NotBefore) {
			t.Errorf("Metadata.NotBefore mismatch")
		}
		if !rawEntry.Metadata.NotAfter.Equal(*newEntry.NotAfter) {
			t.Errorf("Metadata.NotAfter mismatch")
		}
	})

	t.Run("KMS_Encrypt_Fails", func(t *testing.T) {
		newEntry := newEntryBase
		kmsError := fmt.Errorf("kms encryption error")
		mockKms.EncryptFunc = func(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error) {
			return nil, kmsError
		}
		mockDdb.PutItemFunc = nil // Should not be called

		_, err := sg.Create(ctx, newEntry)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
		if !strings.Contains(err.Error(), "KMS encryption failed") {
			t.Errorf("Expected error message to contain 'KMS encryption failed', got: %s", err.Error())
		}
		if !errors.Is(err, kmsError) {
			t.Errorf("Expected error to wrap original KMS error, got: %v", err)
		}
	})

	t.Run("DynamoDB_PutItem_ConditionalCheckFailed", func(t *testing.T) {
		newEntry := newEntryBase
		mockKms.EncryptFunc = func(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error) {
			return &kmssvc.EncryptOutput{CiphertextBlob: []byte("test-ciphertext")}, nil
		}
		mockDdb.PutItemFunc = func(ctx context.Context, params *ddbsvc.PutItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.PutItemOutput, error) {
			return nil, &ddbtypes.ConditionalCheckFailedException{}
		}

		_, err := sg.Create(ctx, newEntry)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
		if !errors.Is(err, exceptions.ErrAlreadyExists) {
			t.Errorf("Expected exceptions.ErrAlreadyExists, got %v", err)
		}
	})

	t.Run("DynamoDB_PutItem_OtherError", func(t *testing.T) {
		newEntry := newEntryBase
		ddbError := fmt.Errorf("some other dynamo error")
		mockKms.EncryptFunc = func(ctx context.Context, params *kmssvc.EncryptInput, optFns ...func(*kmssvc.Options)) (*kmssvc.EncryptOutput, error) {
			return &kmssvc.EncryptOutput{CiphertextBlob: []byte("test-ciphertext")}, nil
		}
		mockDdb.PutItemFunc = func(ctx context.Context, params *ddbsvc.PutItemInput, optFns ...func(*ddbsvc.Options)) (*ddbsvc.PutItemOutput, error) {
			return nil, ddbError
		}

		_, err := sg.Create(ctx, newEntry)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
		if !strings.Contains(err.Error(), "DynamoDB PutItem failed") {
			t.Errorf("Expected error message to contain 'DynamoDB PutItem failed', got: %s", err.Error())
		}
		if !errors.Is(err, ddbError) {
			t.Errorf("Expected error to wrap original DDB error, got: %v", err)
		}
	})

	t.Run("InputValidation_NameEmpty", func(t *testing.T) {
		invalidEntry := types.NewSecretEntry{
			Identifier: types.SecretIdentifier{Name: ""}, // Empty name
			Value:      secretValue,
		}
		_, err := sg.Create(ctx, invalidEntry)
		if err == nil {
			t.Fatal("Expected error for empty name, got nil")
		}
		if !strings.Contains(err.Error(), "Name cannot be empty") {
			t.Errorf("Expected error message for empty name, got: %s", err.Error())
		}
	})

	t.Run("InputValidation_ValueEmpty", func(t *testing.T) {
		invalidEntry := types.NewSecretEntry{
			Identifier: types.SecretIdentifier{Name: secretName},
			Value:      []byte{}, // Empty value
		}
		_, err := sg.Create(ctx, invalidEntry)
		if err == nil {
			t.Fatal("Expected error for empty value, got nil")
		}
		if !strings.Contains(err.Error(), "Value cannot be empty") {
			t.Errorf("Expected error message for empty value, got: %s", err.Error())
		}
	})
}
