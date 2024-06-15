package main

import (
	"bufio"
	"fmt"
	"github.com/angellllk/go-vault/vault"
	"os"
	"strings"
)

func main() {
	var v vault.Vault

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("CLI is running.")

	for {
		flags := vault.InitFlags()

		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := scanner.Text()
		args := strings.Fields(input)
		if len(args) < 1 {
			continue
		}

		command := args[0]

		var err error

		switch command {
		case "setup":
			if len(args) == 1 {
				fmt.Println(vault.SetupUsage)
				continue
			}

			if len(args) > 1 {
				if args[1] != "-s" && args[1] != "-o" {
					fmt.Println(vault.SetupUsage)
					continue
				}
			}

			err = flags.SetupCmd.Parse(args[1:])
			if err != nil {
				continue
			}

			err = v.Setup([]byte(*flags.Setup.Secret), *flags.Setup.Output)
			if err != nil {
				fmt.Println("error:", err)
			}

			fmt.Println("Vault initialised. Output file:", v.OutputF)

		case "add":
			if v.Cipher == nil {
				fmt.Println("error: you need to setup the vault first.")
				continue
			}

			if len(args) == 1 {
				fmt.Println(vault.AddUsage)
				continue
			}

			if len(args) > 1 {
				if args[1] != "-u" && args[1] != "-p" && args[1] != "-w" {
					fmt.Println(vault.AddUsage)
					continue
				}
			}

			err = flags.AddCmd.Parse(args[1:])
			if err != nil {
				continue
			}

			err = v.Add(*flags.Add.Username, *flags.Add.Password, *flags.Add.Website)
			if err != nil {
				fmt.Println("error:", err)
				continue
			}

		case "reset":
			if v.Cipher == nil {
				fmt.Println("error: you need to setup the vault first.")
				continue
			}

			if len(args) < 2 {
				fmt.Println("warning: resetting the vault means complete deletion. Use reset confirm to confirm.")
				continue
			}

			if args[1] != "confirm" {
				continue
			}

			err = v.Reset()
			if err != nil {
				fmt.Println("error:", err)
				continue
			}

		case "help":
			if len(args) < 2 {
				fmt.Println(vault.HelpUsage + vault.AvailableCmd)
				continue
			}

			err = v.Help(args[1])
			if err != nil {
				fmt.Println("error:", err)
				continue
			}

		default:
			fmt.Println("error: unknown command. Use help")
		}

		if err = scanner.Err(); err != nil {
			fmt.Println("Error reading input:", err)
		}
	}
}
