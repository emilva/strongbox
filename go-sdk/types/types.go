// Package types defines the data structures and type aliases used throughout the Strongbox Go SDK.
// These types are used for identifying resources, passing data to SDK methods, and returning results.
package types

import "time"

// SecretsGroupIdentifier uniquely identifies a secrets group.
// It consists of a region and a name, which together define the scope of the group.
type SecretsGroupIdentifier struct {
	// Region is the AWS region where the secrets group resides.
	Region string
	// Name is the user-defined name for the secrets group.
	Name string
}

// SecretsGroupInfo contains metadata about a secrets group.
type SecretsGroupInfo struct {
	// Identifier is the SecretsGroupIdentifier for this group.
	Identifier SecretsGroupIdentifier
	// ARN is the Amazon Resource Name (ARN) of the primary resource backing this group (e.g., KMS Key ARN).
	ARN string
	// CreatedAt is the timestamp when the secrets group was created.
	CreatedAt time.Time
}

// Principal represents an entity (e.g., AWS account, IAM user/role) that can be granted access
// to Strongbox resources.
type Principal struct {
	// Type specifies the type of the principal, e.g., "AWS_ACCOUNT", "IAM_USER", "IAM_ROLE".
	Type string
	// ID is the unique identifier for the principal, e.g., an AWS account ID or IAM user/role ARN.
	ID string
}

// SecretIdentifier uniquely identifies a secret within a secrets group.
type SecretIdentifier struct {
	// Name is the user-defined name for the secret.
	Name string
}

// SRN (Strongbox Resource Name) provides a unique, opaque identifier for a secret version
// that can be used for direct retrieval or referencing.
type SRN struct {
	// Raw is the raw string representation of the Strongbox Resource Name.
	Raw string
}

// NewSecretEntry defines the information required to create a new secret or a new version of an existing secret.
type NewSecretEntry struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Value is the actual secret data (plaintext). This will be encrypted by the SDK.
	Value []byte
	// SecretType is a MIME type or custom string indicating the type of the secret data (e.g., "text/plain", "application/json", "BINARY").
	SecretType string
	// Comment is an optional user-provided comment about the secret or this version.
	Comment string `json:"comment,omitempty"`
	// NotBefore is an optional timestamp indicating when this secret version becomes active.
	// If nil, the secret version is active immediately upon creation (unless explicitly disabled).
	NotBefore *time.Time `json:"notBefore,omitempty"`
	// NotAfter is an optional timestamp indicating when this secret version expires.
	// If nil, the secret version does not expire.
	NotAfter *time.Time `json:"notAfter,omitempty"`
	// UserData is an optional map of key-value pairs for storing custom metadata.
	UserData map[string]string `json:"userData,omitempty"`
}

// RawSecretEntry represents a secret as it is stored, typically with encrypted data.
// This struct is often used when listing secrets without immediate decryption.
type RawSecretEntry struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Version is the specific version number of this secret entry.
	Version int64
	// EncryptedData is the encrypted secret value.
	EncryptedData []byte
	// Metadata contains all metadata associated with this secret version.
	Metadata SecretMetadata
}

// SecretEntry represents a decrypted secret, including its plaintext value and metadata.
type SecretEntry struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Version is the specific version number of this secret entry.
	Version int64
	// SecretValue is the decrypted plaintext secret data.
	SecretValue []byte
	// SecretType is a MIME type or custom string indicating the type of the secret data.
	SecretType string
	// Metadata contains all metadata associated with this secret version.
	Metadata SecretMetadata
}

// SecretMetadata contains all metadata associated with a specific version of a secret.
type SecretMetadata struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Version is the specific version number of this secret entry.
	Version int64
	// State indicates the current lifecycle state of the secret version (e.g., "ENABLED", "DISABLED").
	State string // Consider using SecretState type here for type safety
	// CreatedAt is the timestamp when this secret version was created.
	CreatedAt time.Time
	// CreatedBy is the principal that created this secret version. May be empty if not available.
	CreatedBy Principal `json:"createdBy,omitempty"`
	// LastUpdatedAt is the timestamp when this secret version was last updated.
	LastUpdatedAt time.Time `json:"lastUpdatedAt,omitempty"`
	// NotBefore indicates when this secret version becomes active.
	NotBefore *time.Time `json:"notBefore,omitempty"`
	// NotAfter indicates when this secret version expires.
	NotAfter *time.Time `json:"notAfter,omitempty"`
	// Comment is a user-provided comment about this secret version.
	Comment string `json:"comment,omitempty"`
	// UserData is a map of key-value pairs for custom metadata.
	UserData map[string]string `json:"userData,omitempty"`
	// KMSEncryptionContextJSON is the JSON string representation of the KMS encryption context
	// used when this secret version was encrypted. This is crucial for decryption.
	KMSEncryptionContextJSON string `json:"kmsEncryptionContextJson,omitempty" dynamodbav:"KMSEncryptionContextJSON,omitempty"`
	// SecretType is a MIME type or custom string indicating the type of the secret data.
	// This field is populated from dynamoSecretItem.SecretType during retrieval.
	SecretType string `json:"secretType,omitempty" dynamodbav:"SecretType,omitempty"`
}

// StringSecretEntry is a convenience struct for secrets retrieved as strings by SimpleSecretsGroup.
type StringSecretEntry struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Version is the specific version number of this secret entry.
	Version int64
	// Value is the decrypted secret value as a string.
	Value string
}

// ByteSecretEntry is a convenience struct for secrets retrieved as byte slices by SimpleSecretsGroup.
type ByteSecretEntry struct {
	// Identifier is the name of the secret.
	Identifier SecretIdentifier
	// Version is the specific version number of this secret entry.
	Version int64
	// Value is the decrypted secret value as a byte slice.
	Value []byte
}

// CurrentTime returns the current local time.
// This function can be used by stub implementations or default value initializations.
// Note: For actual timestamps stored in backend systems, UTC is generally preferred.
// This helper returns local time, which might be adjusted by the SDK components to UTC if necessary.
func CurrentTime() time.Time {
	return time.Now()
}

// SecretState defines the lifecycle state of a secret version.
type SecretState string

const (
	// StateEnabled indicates the secret version is active and can be used.
	StateEnabled SecretState = "ENABLED"
	// StateDisabled indicates the secret version is disabled and cannot be used for new decryptions
	// (unless explicitly allowed by a specific decryption method).
	StateDisabled SecretState = "DISABLED"
	// Potentially other states like PENDING_DELETION, etc.
)

// SecretMimeType defines common MIME types for secrets, used in the SecretType field
// of NewSecretEntry and SecretEntry.
type SecretMimeType string

const (
	// SecretTypeString indicates the secret is a plaintext string, typically UTF-8 encoded.
	// Corresponds to "text/plain".
	SecretTypeString SecretMimeType = "text/plain"
	// SecretTypeBinary indicates the secret is arbitrary binary data.
	// Corresponds to "application/octet-stream".
	SecretTypeBinary SecretMimeType = "application/octet-stream"
	// Add other common types like application/json, etc. as needed.
)

// ClientConfiguration holds configuration options for the Strongbox client.
// Currently a placeholder; can be expanded with options like retry strategies, logging levels, etc.
type ClientConfiguration struct {
	// Region specifies the AWS region for operations if not overridden by specific identifiers.
	Region string
	// SecretsTableName is the name of the DynamoDB table where secret metadata and encrypted values are stored.
	SecretsTableName string
	// Add other client-specific configurations here, e.g., custom HTTP client, retry settings.
}

// Comment is a type alias for string, representing a user-provided comment.
// This is used in various metadata structures.
type Comment string

// UserAlias is a type alias for string, representing a user-defined alias for a resource.
// (Currently not used, but defined as per prompt)
type UserAlias string

// ProfileIdentifier is a type alias for string, representing a configuration profile name.
// (Currently not used, but defined as per prompt)
type ProfileIdentifier string

// SecretValue is a type alias for []byte, representing the actual secret data.
// (Currently not used directly in public API in favor of NewSecretEntry.Value, but defined as per prompt)
type SecretValue []byte

// Encoding is a type alias for string, representing the encoding of a secret (e.g., "UTF-8", "base64").
// (Currently not used, but defined as per prompt)
type Encoding string

// EncryptionStrength is a type alias for string, representing the encryption strength (e.g., "AES_256").
// (Currently not used, but defined as per prompt)
type EncryptionStrength string
