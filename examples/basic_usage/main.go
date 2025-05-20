package main

import (
	"context"
	"fmt"
	"log"
	"time" 

	"github.com/aws/aws-sdk-go-v2/config"
	strongboxsdk "github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk" 
	strongboxtypes "github.com/SchibstedEdsProd/strongbox-sdk-java/go-sdk/types"
)

func main() {
	ctx := context.Background()
	log.Println("Starting Strongbox SDK example")

	// --- 1. Load AWS Configuration ---
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	if awsCfg.Region == "" {
		awsCfg.Region = "us-east-1" 
		log.Printf("AWS Region not set, defaulting to %s. Please configure your AWS region.", awsCfg.Region)
	}
	log.Printf("Using AWS Region: %s", awsCfg.Region)


	// --- 2. Initialize SecretsGroupManager ---
	secretsTableName := "strongbox-example-secrets-table-CHANGE-ME" // Ensure this table exists or can be created
	manager, err := strongboxsdk.NewDefaultSecretsGroupManager(ctx, awsCfg, secretsTableName)
	if err != nil {
		log.Fatalf("Failed to create SecretsGroupManager: %v", err)
	}
	log.Println("SecretsGroupManager initialized")

	// --- 3. Define SecretsGroup Identifier ---
	groupRegion := awsCfg.Region 
	groupName := fmt.Sprintf("example-sdk-group-%d", time.Now().UnixNano()) 
	groupIdentifier := strongboxtypes.SecretsGroupIdentifier{
		Region: groupRegion,
		Name:   groupName,
	}
	log.Printf("Operating on Secrets Group: %s in region %s", groupName, groupRegion)

	// --- 4. Create Secrets Group ---
	_, err = manager.Create(ctx, groupIdentifier)
	if err != nil {
		log.Printf("Failed to create SecretsGroup %s (it might already exist): %v", groupName, err)
        _, getErr := manager.Info(ctx, groupIdentifier)
        if getErr != nil {
            log.Fatalf("Could not create or get info for group %s. Halting example. Error on Get: %v", groupName, getErr)
        }
        log.Printf("SecretsGroup %s already exists or was accessible, proceeding.", groupName)
	} else {
		log.Printf("Successfully created SecretsGroup: %s", groupName)
	}


	// --- 5. Get the SecretsGroup instance ---
	secretsGroup, err := manager.Get(ctx, groupIdentifier)
	if err != nil {
		log.Fatalf("Failed to get SecretsGroup %s: %v", groupName, err)
	}
	log.Printf("Successfully got SecretsGroup instance for: %s", groupName)
	
	// --- 6. Add a String Secret ---
	secretName := "MyExampleStringSecret"
	secretIdentifier := strongboxtypes.SecretIdentifier{Name: secretName}
	secretStringValue := "This is a secret string from the Go SDK example!"
	
	newSecretEntry := strongboxtypes.NewSecretEntry{
		Identifier: secretIdentifier,
		Value:      []byte(secretStringValue),
		SecretType: string(strongboxtypes.SecretTypeString), 
		Comment:    "Example secret added by Go SDK",
	}
	rawEntry, err := secretsGroup.Create(ctx, newSecretEntry)
	if err != nil {
		log.Fatalf("Failed to create secret %s: %v", secretName, err)
	}
	log.Printf("Successfully created secret %s version %d", secretName, rawEntry.Version)

	// --- 7. Retrieve the String Secret (using SimpleSecretsGroup methods) ---
	// DefaultSecretsGroup implements SimpleSecretsGroup, so secretsGroup can be used directly.
	retrievedString, found, err := secretsGroup.GetStringSecret(ctx, secretIdentifier)
	if err != nil {
		log.Fatalf("Error retrieving string secret %s: %v", secretName, err)
	}
	if !found {
		log.Printf("String secret %s not found.", secretName)
	} else {
		log.Printf("Retrieved string secret %s: '%s'", secretName, retrievedString)
		if retrievedString != secretStringValue {
			log.Printf("ERROR: Retrieved string '%s' does not match original '%s'", retrievedString, secretStringValue)
		}
	}
    
    // --- Optional: Add another version ---
    updatedSecretStringValue := "This is version 2 of the secret!"
    addVersionEntry := strongboxtypes.NewSecretEntry{
        Identifier: secretIdentifier,
        Value:      []byte(updatedSecretStringValue),
        SecretType: string(strongboxtypes.SecretTypeString),
        Comment:    "Version 2 of example secret",
    }
    v2RawEntry, err := secretsGroup.AddVersion(ctx, addVersionEntry)
    if err != nil {
        log.Printf("Failed to add version 2 for secret %s: %v", secretName, err)
    } else {
        log.Printf("Successfully added version %d for secret %s", v2RawEntry.Version, secretName)
        
        retrievedV2String, foundV2, errV2 := secretsGroup.GetStringSecret(ctx, secretIdentifier)
        if errV2 != nil { log.Fatalf("Error retrieving v2 string secret %s: %v", secretName, errV2) }
        if !foundV2 { log.Printf("V2 string secret %s not found.", secretName) }
        if foundV2 && retrievedV2String == updatedSecretStringValue {
            log.Printf("Successfully retrieved latest (v2) string secret: '%s'", retrievedV2String)
        } else if foundV2 {
            log.Printf("ERROR: Retrieved v2 string '%s' does not match expected '%s'", retrievedV2String, updatedSecretStringValue)
        }
    }

	// --- 8. Delete the Secret (all versions) ---
	log.Printf("Deleting secret %s (all versions)...", secretName)
	err = secretsGroup.Delete(ctx, secretIdentifier)
	if err != nil {
		log.Fatalf("Failed to delete secret %s: %v", secretName, err)
	}
	log.Printf("Successfully deleted secret %s", secretName)

	_, foundAfterDelete, _ := secretsGroup.GetStringSecret(ctx, secretIdentifier)
	if foundAfterDelete {
		log.Printf("ERROR: Secret %s still found after deletion!", secretName)
	} else {
		log.Printf("Secret %s confirmed deleted (not found).", secretName)
	}

	// --- 9. Delete the Secrets Group ---
	log.Printf("Deleting SecretsGroup %s...", groupName)
	err = manager.Delete(ctx, groupIdentifier)
	if err != nil {
		log.Fatalf("Failed to delete SecretsGroup %s: %v", groupName, err)
	}
	log.Printf("Successfully initiated deletion of SecretsGroup: %s", groupName)
    log.Println("Strongbox SDK example finished.")
}
