package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"strings"
	"syscall"
)

const availableCommands = "the commands available are: init, reset, help"
const initUsage = "usage: \ngo-vault init [secret] [output.json]"
const resetUsage = "usage: \ngo-vault reset"
const helpUsage = "usage: \ngo-vault help <command>\n\n"

type Vault struct {
	Nonce   []byte
	Cipher  cipher.AEAD
	OutputF string
}

func Start() {
	if len(os.Args) < 2 {
		usage := "usage:\n\n\tgo-vault <command> [arguments]\n\n" + availableCommands
		fmt.Print(usage)
		return
	}

	command := os.Args[1]

	var vault Vault
	var err error

	switch command {
	case "init":
		if len(os.Args) < 3 {
			fmt.Println(initUsage)
			return
		}

		err = vault.initVault([]byte(os.Args[2]), os.Args[3])
		if err != nil {
			fmt.Println("error:", err)
		}

	case "reset":
		if len(os.Args) < 3 {
			fmt.Println("warning: resetting the vault means complete deletion. Use go-vault reset confirm to confirm.")
			return
		}

		if os.Args[2] != "confirm" {
			return
		}

		err := os.Remove("vault.json")
		if err != nil {
			fmt.Println(err.Error())
			return
		}

	case "help":
		if len(os.Args) < 3 {
			fmt.Println(helpUsage + availableCommands)
			return
		}

		vault.getHelp(os.Args[2])

	default:
		fmt.Printf("error: unknown command: %s. Use go-vault help ", command)
	}
}

func (v *Vault) initVault(secret []byte, output string) error {
	errCheck := v.checkFile(output)
	if errCheck != nil {
		return errCheck
	}

	hash, err := v.checkForSecret(secret)
	if err != nil {
		return err
	}

	err = v.saveSecret(hash)
	if err != nil {
		return err
	}

	v.Cipher, err = chacha20poly1305.New(hash)
	if err != nil {
		return err
	}

	v.Nonce = make([]byte, chacha20.NonceSize)
	_, errRead := rand.Read(v.Nonce)
	if errRead != nil {
		return errRead
	}

	return nil
}

func (v *Vault) checkFile(output string) error {
	if len(output) == 0 {
		v.OutputF = "vault.json"
		return nil
	}

	sep := strings.Split(output, ".")

	switch len(sep) {
	case 2:
		if !strings.EqualFold(sep[1], "json") {
			return errors.New("error: invalid output file type. Only .json format is accepted")
		}

		v.OutputF = output

	default:
		return errors.New("error: invalid output file provided")
	}

	return nil
}

func (v *Vault) checkForSecret(secret []byte) ([]byte, error) {
	secretJson, errRead := os.ReadFile(v.OutputF)
	if errRead != nil && !errors.Is(errRead, syscall.Errno(2)) {
		return nil, errRead
	}

	// There's no secret created
	if len(secretJson) == 0 {
		return argon2.IDKey(secret, nil, 1, 64*1024, 4, 32), nil
	}

	// Get the secret
	secretMap := make(map[string]string)
	errUnmarshal := json.Unmarshal(secretJson, &secretMap)
	if errUnmarshal != nil {
		return nil, errUnmarshal
	}

	hash := []byte(secretMap["secret"])
	if len(hash) == 0 {
		return nil, nil
	}

	// Validate the secret found with the received
	validated, ok := v.validate(secret, hash)
	if !ok {
		return nil, errors.New("invalid secret provided")
	}

	return validated, nil
}

func (v *Vault) validate(secret, retHash []byte) ([]byte, bool) {
	decodedHash := make([]byte, base64.StdEncoding.DecodedLen(len(retHash)))
	_, errDecode := base64.StdEncoding.Decode(decodedHash, retHash)
	if errDecode != nil {
		return nil, false
	}

	var padding int
	getPadding(string(retHash), 1, &padding)

	decodedHash = decodedHash[:len(decodedHash)-padding]
	hash := argon2.IDKey(secret, nil, 1, 64*1024, 4, 32)

	return hash, bytes.Equal(hash, decodedHash)
}

func getPadding(b64enc string, i int, ret *int) {
	c := b64enc[len(b64enc)-i]
	if string(c) != "=" {
		return
	}

	if string(c) == "=" {
		*ret++
		getPadding(b64enc[:len(b64enc)-i], i+1, ret)
	}

}

func (v *Vault) saveSecret(ciphertext []byte) error {
	// Save the encrypted secret to disk
	secretMap := make(map[string][]byte)
	secretMap["secret"] = ciphertext

	secretJson, errMarshal := json.Marshal(secretMap)
	if errMarshal != nil {
		return errMarshal
	}

	err := os.WriteFile(v.OutputF, secretJson, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) getHelp(command string) {
	switch command {
	case "init":
		fmt.Println(initUsage + "\n\n" + "\tinit starts the vault with the \"secret\" passed argument to be used in further cryptographic operations.")

	case "reset":
		fmt.Println(resetUsage + "\n\n" + "\treset will reset the vault by removing the secret and all the saved data.")

	default:
		fmt.Println(helpUsage + availableCommands)
	}
}
