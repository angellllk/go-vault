package vault

import (
	"testing"
)

func TestInit(t *testing.T) {
	output := "test.json"

	valid := []byte("secret")
	invalid := []byte("invalid")

	var v Vault
	err := v.Setup(valid, output)
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
			err := v.Setup(tt.args.secret, tt.args.output)
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
