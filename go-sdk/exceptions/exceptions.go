// Package exceptions defines common error types used across the Strongbox Go SDK.
// These errors provide more specific information than generic errors and can be
// checked using errors.Is.
package exceptions

import "errors"

var (
	// ErrNotFound indicates that a requested resource (e.g., secret, secret group) was not found.
	ErrNotFound = errors.New("strongbox: resource not found")
	// ErrAlreadyExists indicates that an attempt was made to create a resource that already exists.
	ErrAlreadyExists = errors.New("strongbox: resource already exists")
	// ErrEncoding indicates an error during data encoding or decoding (e.g., JSON marshaling/unmarshaling issues).
	ErrEncoding = errors.New("strongbox: encoding/decoding error")
	// ErrIO indicates a general input/output error, potentially from network or file system operations.
	ErrIO = errors.New("strongbox: I/O error")
	// ErrPermissionDenied indicates that the caller does not have sufficient permissions to perform the requested operation.
	ErrPermissionDenied = errors.New("strongbox: permission denied")
	// ErrConfiguration indicates an issue with the SDK's or service's configuration.
	ErrConfiguration = errors.New("strongbox: configuration error")
	// ErrIntegrity indicates a data integrity violation or mismatch, such as a failed checksum or an unexpected data format.
	ErrIntegrity = errors.New("strongbox: data integrity violation or mismatch")
	// ErrPotentiallyMaliciousData indicates that data encountered during processing might be improperly formatted or malicious.
	ErrPotentiallyMaliciousData = errors.New("strongbox: potentially malicious data detected")
	// ErrSecretNotActive indicates that a secret version is not currently active (e.g., disabled, outside validity period).
	ErrSecretNotActive = errors.New("strongbox: secret is not active or outside validity period")
	// ErrNotImplemented indicates that a requested functionality is not yet implemented.
	ErrNotImplemented = errors.New("strongbox: functionality not implemented")
	// ErrConflict indicates that an operation could not be completed due to a conflict with the current state of the resource,
	// often due to concurrent modifications.
	ErrConflict = errors.New("strongbox: conflict during update, concurrent modification likely")
)
