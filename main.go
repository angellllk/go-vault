package main

import (
	"fmt"
	"github.com/angellllk/go-vault/vault"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage := "usage:\n\n\tgo-vault <command> [arguments]\n\n" + vault.AvailableCmd
		fmt.Print(usage)
		return
	}

	command := os.Args[1]

	var v vault.Vault
	var err error

	switch command {
	case "setup":
		if len(os.Args) < 3 {
			fmt.Println(vault.SetupUsage)
			return
		}

		err = v.Setup([]byte(os.Args[2]), os.Args[3])
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

		err = os.Remove("vault.json")
		if err != nil {
			fmt.Println(err.Error())
			return
		}

	case "help":
		if len(os.Args) < 3 {
			fmt.Println(vault.HelpUsage + vault.AvailableCmd)
			return
		}

		v.Help(os.Args[2])

	default:
		fmt.Printf("error: unknown command: %s. Use go-vault help ", command)
	}
}
