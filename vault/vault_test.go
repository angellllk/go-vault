package vault

import (
	"testing"
)

func TestVault_Setup(t *testing.T) {
	testVault := testGetVault(t)
	defer testCleanup(t, testVault.OutputF)

	type args struct {
		secret []byte
		output string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"setup-command-works",
			args{
				secret: []byte(testSecret),
				output: testOutput,
			},
			false,
		},
		{
			"setup-command-invalid",
			args{
				secret: []byte("invalid"),
				output: testOutput,
			},
			true,
		},
		{
			"setup-empty-secret",
			args{
				secret: nil,
				output: testOutput,
			},
			true,
		},
		{
			"setup-invalid-output-file",
			args{
				secret: []byte(testSecret),
				output: "invalid.format.txt",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := testVault.Setup(tt.args.secret, tt.args.output)
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

func TestVault_Reset(t *testing.T) {
	testVault := testGetVault(t)

	err := testVault.Reset()
	if err != nil {
		t.Fatal(err.Error())
	}

	err = testVault.Reset()
	if err != nil {
		t.Log(err.Error())
	}
}

func TestVault_Help(t *testing.T) {
	testVault := testGetVault(t)
	defer testCleanup(t, testVault.OutputF)

	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{
			"help-setup-works",
			"setup",
			false,
		},
		{
			"help-reset-works",
			"reset",
			false,
		},
		{
			"help-invalid-cmd",
			"test",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := testVault.Help(tt.command)
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
