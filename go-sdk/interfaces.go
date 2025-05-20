// Package strongbox provides the Go SDK for interacting with Strongbox services.
// This file defines the core interfaces for managing secret groups and secrets.
package strongbox

import (
	"context"
	// Ensure types package is correctly referenced if it's external or aliased.
	// Assuming it's "go-sdk/types" as per previous setup.
	"go-sdk/types"
)

// SecretsGroupManager manages the lifecycle of secrets groups.
// A secrets group typically corresponds to a KMS key and an associated alias,
// and contains multiple secrets.
type SecretsGroupManager interface {
	// Create creates a new secrets group (e.g., a KMS key and alias).
	// ctx: Context for the operation.
	// group: Identifier for the group to be created.
	// Returns information about the created group or an error.
	Create(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error)

	// Get retrieves a handle to an existing secrets group, allowing operations on secrets within it.
	// ctx: Context for the operation.
	// group: Identifier for the group to retrieve.
	// Returns a SecretsGroup instance or an error if the group cannot be accessed.
	Get(ctx context.Context, group types.SecretsGroupIdentifier) (SecretsGroup, error)

	// Identifiers lists the identifiers of all secrets groups managed by this manager
	// (typically filtered by a common prefix or tag in the underlying backend).
	// ctx: Context for the operation.
	// Returns a slice of group identifiers or an error.
	Identifiers(ctx context.Context) ([]types.SecretsGroupIdentifier, error)

	// Info retrieves metadata about a specific secrets group (e.g., ARN, creation date).
	// ctx: Context for the operation.
	// group: Identifier for the group.
	// Returns detailed information about the group or an error.
	Info(ctx context.Context, group types.SecretsGroupIdentifier) (types.SecretsGroupInfo, error)

	// Delete schedules the deletion of a secrets group (e.g., its KMS key) and removes associated resources like aliases.
	// ctx: Context for the operation.
	// group: Identifier for the group to be deleted.
	// Returns an error if deletion fails.
	Delete(ctx context.Context, group types.SecretsGroupIdentifier) error

	// AttachAdmin grants administrative permissions (e.g., kms:*) on the secrets group's underlying resources
	// to the specified principal.
	// ctx: Context for the operation.
	// group: Identifier for the group.
	// principal: The principal to grant admin access.
	// Returns an error if the operation fails.
	AttachAdmin(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error

	// DetachAdmin revokes administrative permissions from the specified principal for the secrets group.
	// ctx: Context for the operation.
	// group: Identifier for the group.
	// principal: The principal whose admin access is to be revoked.
	// Returns an error if the operation fails.
	DetachAdmin(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error

	// AttachReadOnly grants read-only permissions (e.g., kms:Decrypt, kms:DescribeKey) on the secrets group's
	// underlying resources to the specified principal.
	// ctx: Context for the operation.
	// group: Identifier for the group.
	// principal: The principal to grant read-only access.
	// Returns an error if the operation fails.
	AttachReadOnly(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error

	// DetachReadOnly revokes read-only permissions from the specified principal for the secrets group.
	// ctx: Context for the operation.
	// group: Identifier for the group.
	// principal: The principal whose read-only access is to be revoked.
	// Returns an error if the operation fails.
	DetachReadOnly(ctx context.Context, group types.SecretsGroupIdentifier, principal types.Principal) error
}

// SecretsGroup manages secrets within a specific group.
// It provides methods for creating, versioning, updating, retrieving, and deleting secrets.
type SecretsGroup interface {
	// Create creates the first version of a new secret.
	// ctx: Context for the operation.
	// newSecretEntry: Contains the secret's name, value, type, and other metadata.
	// Returns a RawSecretEntry containing the encrypted data and metadata of the new secret version, or an error.
	Create(ctx context.Context, newSecretEntry types.NewSecretEntry) (types.RawSecretEntry, error)

	// AddVersion creates a new version of an existing secret.
	// ctx: Context for the operation.
	// newSecretEntry: Contains the secret's name, new value, type, and other metadata.
	// Returns a RawSecretEntry for the new version or an error.
	AddVersion(ctx context.Context, newSecretEntry types.NewSecretEntry) (types.RawSecretEntry, error)

	// Update modifies the metadata of an existing secret version (e.g., comment, state, NotBefore/NotAfter, UserData).
	// The secret value itself (EncryptedData) is not modified by this operation.
	// ctx: Context for the operation.
	// secretMetadata: The metadata to update. Identifier and Version must specify the target secret version.
	// Returns a RawSecretEntry with the updated metadata or an error.
	Update(ctx context.Context, secretMetadata types.SecretMetadata) (types.RawSecretEntry, error)

	// Identifiers lists the names (identifiers) of all secrets within this group.
	// ctx: Context for the operation.
	// Returns a slice of secret identifiers or an error.
	Identifiers(ctx context.Context) ([]types.SecretIdentifier, error)

	// Delete removes all versions of a specific secret from the group.
	// ctx: Context for the operation.
	// secretIdentifier: The identifier of the secret to delete.
	// Returns an error if deletion fails.
	Delete(ctx context.Context, secretIdentifier types.SecretIdentifier) error

	// ListSecrets retrieves all versions of all secrets within this group.
	// This can be a resource-intensive operation for groups with many secrets/versions.
	// Consider using Identifiers and then fetching specific secrets if needed.
	// ctx: Context for the operation.
	// Returns a slice of RawSecretEntry (containing encrypted data) or an error.
	ListSecrets(ctx context.Context) ([]types.RawSecretEntry, error)

	// Decrypt decrypts a RawSecretEntry, returning a SecretEntry with the plaintext value.
	// It performs integrity checks on the identifier and version.
	// This method is typically used internally by getters but is exposed for advanced scenarios.
	// The caller is responsible for ensuring the rawSecretEntry's metadata, especially KMSEncryptionContextJSON, is correct.
	// ctx: Context for the operation.
	// rawSecretEntry: The raw secret data with encrypted value and metadata.
	// expectedSecretIdentifier: The expected name of the secret.
	// expectedVersion: The expected version of the secret.
	// Returns the decrypted SecretEntry or an error (e.g., if integrity checks fail or decryption fails).
	Decrypt(ctx context.Context, rawSecretEntry types.RawSecretEntry, expectedSecretIdentifier types.SecretIdentifier, expectedVersion int64) (types.SecretEntry, error)

	// DecryptEvenIfNotActive decrypts a RawSecretEntry, similar to Decrypt, but may bypass
	// checks for the secret's "active" status (e.g., State, NotBefore, NotAfter).
	// Use with caution, primarily for administrative or recovery purposes.
	// ctx: Context for the operation.
	// rawSecretEntry: The raw secret data.
	// expectedSecretIdentifier: The expected name.
	// expectedVersion: The expected version.
	// Returns the decrypted SecretEntry or an error.
	DecryptEvenIfNotActive(ctx context.Context, rawSecretEntry types.RawSecretEntry, expectedSecretIdentifier types.SecretIdentifier, expectedVersion int64) (types.SecretEntry, error)

	// SRN generates the Strongbox Resource Name (SRN) for a given secret identifier within this group.
	// ctx: Context for the operation.
	// secretIdentifier: The identifier of the secret.
	// Returns the SRN or an error.
	SRN(ctx context.Context, secretIdentifier types.SecretIdentifier) (types.SRN, error)

	// GetLatestActiveVersion retrieves, decrypts, and returns the latest active version of a secret.
	// ctx: Context for the operation.
	// secretIdentifier: The identifier of the secret.
	// Returns the decrypted SecretEntry, a boolean indicating if found and active, and an error.
	GetLatestActiveVersion(ctx context.Context, secretIdentifier types.SecretIdentifier) (types.SecretEntry, bool, error)

	// GetActive retrieves, decrypts, and returns a specific version of a secret, provided it is active.
	// ctx: Context for the operation.
	// secretIdentifier: The identifier of the secret.
	// targetVersion: The specific version to retrieve.
	// Returns the decrypted SecretEntry, a boolean indicating if found and active, and an error.
	GetActive(ctx context.Context, secretIdentifier types.SecretIdentifier, targetVersion int64) (types.SecretEntry, bool, error)

	// GetAllActiveVersions retrieves and decrypts all active versions of a specific secret.
	// ctx: Context for the operation.
	// secretIdentifier: The identifier of the secret.
	// Returns a slice of decrypted SecretEntry or an error.
	GetAllActiveVersions(ctx context.Context, secretIdentifier types.SecretIdentifier) ([]types.SecretEntry, error)

	// GetLatestActiveVersionOfAllSecrets retrieves the latest active version of all secrets within this group.
	// This can be resource-intensive.
	// ctx: Context for the operation.
	// Returns a slice of decrypted SecretEntry or an error.
	GetLatestActiveVersionOfAllSecrets(ctx context.Context) ([]types.SecretEntry, error)

	// GetAllActiveVersionsOfAll retrieves all active versions of all secrets within this group.
	// This is likely the most resource-intensive read operation.
	// ctx: Context for the operation.
	// Returns a slice of decrypted SecretEntry or an error.
	GetAllActiveVersionsOfAll(ctx context.Context) ([]types.SecretEntry, error)

	// Close performs any necessary cleanup for the SecretsGroup instance (e.g., closing client connections).
	// ctx: Context for the operation.
	// Returns an error if cleanup fails.
	Close(ctx context.Context) error
}

// SimpleSecretsGroup provides a simplified interface for common secret retrieval operations,
// focusing on getting secrets directly as strings or byte slices.
// This interface is typically implemented by the same struct that implements SecretsGroup.
type SimpleSecretsGroup interface {
	// GetStringSecret retrieves the latest active version of a secret as a string.
	// ctx: Context for the operation.
	// secretIdentifier: The name of the secret.
	// Returns the secret string, a boolean indicating if found and active, and an error.
	GetStringSecret(ctx context.Context, secretIdentifier types.SecretIdentifier) (string, bool, error)
	// GetStringSecretByName is a convenience wrapper for GetStringSecret.
	GetStringSecretByName(ctx context.Context, name string) (string, bool, error)
	// GetStringSecretVersion retrieves a specific active version of a secret as a string.
	GetStringSecretVersion(ctx context.Context, secretIdentifier types.SecretIdentifier, version int64) (string, bool, error)
	// GetStringSecretByNameVersion is a convenience wrapper for GetStringSecretVersion.
	GetStringSecretByNameVersion(ctx context.Context, name string, version int64) (string, bool, error)
	// GetAllStringSecrets retrieves the latest active version of all secrets in the group as string entries.
	// May return exceptions.ErrNotImplemented if not efficiently supported by the backend.
	GetAllStringSecrets(ctx context.Context) ([]types.StringSecretEntry, error)

	// GetBinarySecret retrieves the latest active version of a secret as a byte slice.
	GetBinarySecret(ctx context.Context, secretIdentifier types.SecretIdentifier) ([]byte, bool, error)
	// GetBinarySecretByName is a convenience wrapper for GetBinarySecret.
	GetBinarySecretByName(ctx context.Context, name string) ([]byte, bool, error)
	// GetBinarySecretVersion retrieves a specific active version of a secret as a byte slice.
	GetBinarySecretVersion(ctx context.Context, secretIdentifier types.SecretIdentifier, version int64) ([]byte, bool, error)
	// GetBinarySecretByNameVersion is a convenience wrapper for GetBinarySecretVersion.
	GetBinarySecretByNameVersion(ctx context.Context, name string, version int64) ([]byte, bool, error)
	// GetAllBinarySecrets retrieves the latest active version of all secrets in the group as byte entries.
	// May return exceptions.ErrNotImplemented if not efficiently supported by the backend.
	GetAllBinarySecrets(ctx context.Context) ([]types.ByteSecretEntry, error)
}
