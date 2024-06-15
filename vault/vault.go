package vault

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const AvailableCmd = "the commands available are: setup, add, reset, help"
const SetupUsage = "usage: \n\tsetup -s secret -o output.json"
const AddUsage = "usage: \n\tadd -u username -p password -w website"
const ResetUsage = "usage: \n\treset"
const HelpUsage = "usage: \n\thelp <command>\n\n"

type Vault struct {
	Cipher  cipher.AEAD
	OutputF string
}

type Record struct {
	Username []byte `json:"username"`
	Password []byte `json:"password"`
}

func (v *Vault) Setup(secret []byte, output string) (err error) {
	err = v.checkFile(output)
	if err != nil {
		return err
	}

	var hash []byte
	hash, err = v.checkForSecret(secret)
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

	return nil
}

func (v *Vault) Add(name, pwd, site string) (err error) {
	var encName, encPwd []byte

	encName, err = v.encrypt("username", name)
	if err != nil {
		return err
	}

	encPwd, err = v.encrypt("password", pwd)
	if err != nil {
		return err
	}

	record := Record{
		Username: encName,
		Password: encPwd,
	}

	err = v.saveRecord(site, record)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) Reset() (err error) {
	var files []string
	files, err = findJSONFiles()
	if err != nil {
		return err
	}

	for _, file := range files {
		err = os.Remove(file)
		if err != nil {
			return err
		}
	}

	return err
}

func (v *Vault) Help(command string) error {
	switch command {
	case "setup":
		fmt.Println(SetupUsage + "\n\n" + "setup starts the vault with the \"secret\" passed argument to be used in further cryptographic operations.")

	case "reset":
		fmt.Println(ResetUsage + "\n\n" + "reset will reset the vault by removing the secret and all the saved data.")

	default:
		return errors.New(fmt.Sprintf("that command is not implemented, %s", AvailableCmd))
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
			return errors.New("invalid output file type. Only .json format is accepted")
		}

		v.OutputF = output

	default:
		return errors.New("invalid output file provided")
	}

	return nil
}

func (v *Vault) checkForSecret(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("no secret provided")
	}

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

	secretJson, errMarshal := json.MarshalIndent(secretMap, "", "    ")
	if errMarshal != nil {
		return errMarshal
	}

	err := os.WriteFile(v.OutputF, secretJson, 0600)
	if err != nil {
		return err
	}

	return nil
}

func (v *Vault) encrypt(mapKey string, field string) (encJson []byte, err error) {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	enc := v.Cipher.Seal(nil, nonce, []byte(field), nil)

	cred := make(map[string][]byte)
	cred[mapKey] = enc

	var credJson []byte
	credJson, err = json.Marshal(cred)
	if err != nil {
		return nil, err
	}

	return credJson, nil
}

func (v *Vault) saveRecord(site string, r Record) error {
	vaultJson, err := os.ReadFile(v.OutputF)
	if err != nil {
		return err
	}

	var existingData interface{}

	err = json.Unmarshal(vaultJson, &existingData)
	if err != nil {
		return err
	}

	data := existingData.(map[string]interface{})
	data[site] = r

	updated, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile(v.OutputF, updated, 0644)
	return err
}

func findJSONFiles() ([]string, error) {
	var jsonFiles []string

	root, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Walk through the directory
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if the file has a .json extension
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			jsonFiles = append(jsonFiles, path)
		}
		return nil
	})

	if len(jsonFiles) == 0 {
		return nil, errors.New("no .json files found")
	}

	return jsonFiles, err
}
