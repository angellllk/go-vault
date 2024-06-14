package main

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

func TestInit(t *testing.T) {
	output := "test.json"

	valid := []byte("secret")
	invalid := []byte("invalid")

	var vault Vault
	err := vault.initVault(valid, output)
	if err != nil {
		t.Fatal(err.Error())
	}
	defer testCleanup(t, output)

	type args struct {
		secret []byte
		output string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"init-command-works",
			args{
				secret: valid,
				output: output,
			},
			false,
		},
		{
			"init-command-invalid",
			args{
				secret: invalid,
				output: output,
			},
			true,
		},
		{
			"init-empty-secret",
			args{
				secret: nil,
				output: output,
			},
			true,
		},
		{
			"init-invalid-output-file",
			args{
				secret: valid,
				output: "invalid.format.txt",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := vault.initVault(tt.args.secret, tt.args.output)
			hasError := err != nil
			if hasError != tt.wantErr {
				t.Fatal(err.Error())
			}

			if tt.wantErr {
				t.Log(err.Error())
			}
		})
	}
}
