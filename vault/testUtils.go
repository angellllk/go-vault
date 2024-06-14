package vault

import (
	"os"
	"testing"
)

const testOutput = "test.json"
const testSecret = "secret"

func testCleanup(t *testing.T, output string) {
	err := os.Remove(output)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func testGetVault(t *testing.T) *Vault {
	var testVault Vault
	valid := []byte(testSecret)

	err := testVault.Setup(valid, testOutput)
	if err != nil {
		t.Fatal(err.Error())
	}

	return &testVault
}
