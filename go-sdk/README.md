# Strongbox Go SDK

## Overview

This SDK provides a Go interface to Strongbox, allowing for the management and retrieval of secrets. It interacts with AWS services like KMS (for encryption and key management) and DynamoDB (for secret storage).

The primary components are:
- **`SecretsGroupManager`**: Manages the lifecycle of secret groups (which map to KMS keys). This includes creating groups, deleting them, and managing their access policies (admin/read-only).
- **`SecretsGroup`**: Manages secrets within a specific group. This includes creating, versioning, updating metadata, retrieving (and decrypting), and deleting secrets.
- **`SimpleSecretsGroup`**: A convenience interface (implemented by `SecretsGroup`) for simpler secret retrieval as strings or byte slices.

## Installation

```bash
# (Once the SDK is published to a Go module repository)
# go get github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk 
# For now, using the local replace directive if you have the main repo:
# In your project's go.mod:
# replace github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk => /path/to/local/strongbox-sdk-java/go-sdk
```

## Quick Start

This example demonstrates basic operations like creating a manager, a secrets group, adding a secret, retrieving it, and cleaning up.

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"strongboxsdk "github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk" // Adjust module path as needed
	"strongboxtypes "github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk/types"
)

func main() {
	ctx := context.Background()
	log.Println("Strongbox Go SDK Quick Start")

	// 1. Load AWS Configuration
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	if awsCfg.Region == "" {
		awsCfg.Region = "us-east-1" // Example default
	}
	log.Printf("Using AWS Region: %s", awsCfg.Region)

	// 2. Initialize SecretsGroupManager
	secretsTableName := "strongbox-example-secrets-table" // Replace with your DynamoDB table name
	manager, err := strongboxsdk.NewDefaultSecretsGroupManager(ctx, awsCfg, secretsTableName)
	if err != nil {
		log.Fatalf("Failed to create SecretsGroupManager: %v", err)
	}

	// 3. Define and Create Secrets Group
	groupIdentifier := strongboxtypes.SecretsGroupIdentifier{
		Region: awsCfg.Region,
		Name:   fmt.Sprintf("quickstart-group-%d", time.Now().Unix()),
	}
	log.Printf("Creating/getting group: %s", groupIdentifier.Name)
	_, err = manager.Create(ctx, groupIdentifier)
	if err != nil {
		log.Printf("Create group failed (may already exist): %v", err)
        // Attempt to proceed if it already exists
        if _, getErr := manager.Info(ctx, groupIdentifier); getErr != nil {
             log.Fatalf("Group %s does not exist and could not be created.", groupIdentifier.Name)
        }
	} else {
        log.Printf("Group %s created.", groupIdentifier.Name)
    }


	secretsGroup, err := manager.Get(ctx, groupIdentifier)
	if err != nil {
		log.Fatalf("Failed to get SecretsGroup: %v", err)
	}

	// 4. Add a String Secret
	secretID := strongboxtypes.SecretIdentifier{Name: "MyQuickStartSecret"}
	secretValue := "Hello from Strongbox Go SDK!"
	_, err = secretsGroup.Create(ctx, strongboxtypes.NewSecretEntry{
		Identifier: secretID,
		Value:      []byte(secretValue),
		SecretType: string(strongboxtypes.SecretTypeString),
		Comment:    "Quick start secret",
	})
	if err != nil {
		log.Fatalf("Failed to create secret: %v", err)
	}
	log.Printf("Secret %s created.", secretID.Name)

	// 5. Retrieve the String Secret
	retrievedVal, found, err := secretsGroup.GetStringSecret(ctx, secretID)
	if err != nil {
		log.Fatalf("Failed to retrieve secret: %v", err)
	}
	if !found {
		log.Fatalf("Secret %s not found after creation!", secretID.Name)
	}
	log.Printf("Retrieved secret %s: '%s'", secretID.Name, retrievedVal)

	// 6. Cleanup (optional)
	log.Printf("Cleaning up secret %s...", secretID.Name)
	if err := secretsGroup.Delete(ctx, secretID); err != nil {
		log.Printf("Failed to delete secret %s: %v", secretID.Name, err)
	}
    log.Printf("Cleaning up group %s...", groupIdentifier.Name)
	if err := manager.Delete(ctx, groupIdentifier); err != nil {
		log.Printf("Failed to delete group %s: %v", groupIdentifier.Name, err)
	}
	log.Println("Quick Start finished.")
}
```

## Configuration

The SDK uses the standard AWS SDK for Go v2 configuration model. Ensure your environment is configured with AWS credentials and a default region. This can be done via:
- IAM Roles for EC2 instances or ECS tasks.
- Shared credentials file (`~/.aws/credentials`).
- Environment variables (e.g., `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`).

The `SecretsGroupManager` also requires the name of the DynamoDB table used for storing secret metadata and encrypted values.

## API Overview

### `SecretsGroupManager`
- `NewDefaultSecretsGroupManager(ctx context.Context, cfg aws.Config, secretsTableName string) (*DefaultSecretsGroupManager, error)`: Constructor.
- `Create(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error)`: Creates a new secrets group (KMS key and alias).
- `Get(ctx context.Context, group types.SecretsGroupIdentifier) (SecretsGroup, error)`: Retrieves a handle to a secrets group.
- `Delete(ctx context.Context, group types.SecretsGroupIdentifier) error`: Schedules deletion for the KMS key and removes its alias.
- `Info(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error)`: Gets metadata about a group.
- `Identifiers(ctx context.Context) ([]types.SecretsGroupIdentifier, error)`: Lists all managed group identifiers.
- `AttachAdmin/DetachAdmin(ctx, group, principal)`: Manages admin IAM permissions on the group's KMS key.
- `AttachReadOnly/DetachReadOnly(ctx, group, principal)`: Manages read-only IAM permissions.

### `SecretsGroup` (and `SimpleSecretsGroup`)
- `Create(ctx, entry types.NewSecretEntry) (types.RawSecretEntry, error)`: Creates the first version of a secret.
- `AddVersion(ctx, entry types.NewSecretEntry) (types.RawSecretEntry, error)`: Adds a new version to an existing secret.
- `Update(ctx, metadata types.SecretMetadata) (types.RawSecretEntry, error)`: Updates metadata of a specific secret version.
- `Delete(ctx, id types.SecretIdentifier) error`: Deletes all versions of a secret.
- `GetActive(ctx, id types.SecretIdentifier, version int64) (types.SecretEntry, bool, error)`: Retrieves and decrypts a specific active version.
- `GetLatestActiveVersion(ctx, id types.SecretIdentifier) (types.SecretEntry, bool, error)`: Retrieves the latest active version.
- `GetStringSecret(ctx, id types.SecretIdentifier) (string, bool, error)`: (SimpleSecretsGroup) Gets latest active secret as string.
- `GetBinarySecret(ctx, id types.SecretIdentifier) ([]byte, bool, error)`: (SimpleSecretsGroup) Gets latest active secret as bytes.
- ... and other getters for specific versions or by name.

## Error Handling

Methods generally return an `error` as the last argument. Specific error types (e.g., `exceptions.ErrNotFound`, `exceptions.ErrAlreadyExists`) are defined in the `go-sdk/exceptions` package and can be checked using `errors.Is`.

## Development

(Placeholder for notes on building, testing, contributing if this were a standalone repo section)
- Run tests: `go test ./...` from the `go-sdk` directory.
```
