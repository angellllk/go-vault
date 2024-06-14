package vault

import (
	"os"
	"testing"
)

func testCleanup(t *testing.T, output string) {
	err := os.Remove(output)
	if err != nil {
		t.Fatal(err.Error())
	}
}
