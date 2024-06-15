package vault

import "flag"

type SetupFlags struct {
	Secret *string
	Output *string
}

type AddFlags struct {
	Username *string
	Password *string
	Website  *string
}

type ResetFlags struct {
	Confirm *string
}

type HelpFlags struct {
	Opt *string
}

type Flags struct {
	Setup    SetupFlags
	Add      AddFlags
	SetupCmd *flag.FlagSet
	AddCmd   *flag.FlagSet
}

func InitFlags() Flags {
	// Setup command and flags
	setupCmd := flag.NewFlagSet("setup", flag.ContinueOnError)
	setupFlags := SetupFlags{
		Secret: setupCmd.String("s", "", "Secret of the vault"),
		Output: setupCmd.String("o", "", "Output file of the vault"),
	}

	// Add command and flags
	addCmd := flag.NewFlagSet("add", flag.ContinueOnError)
	addFlags := AddFlags{
		Username: addCmd.String("u", "", "Username to be stored"),
		Password: addCmd.String("p", "", "Password to be stored"),
		Website:  addCmd.String("w", "", "Website address of the credentials"),
	}

	return Flags{
		Setup:    setupFlags,
		Add:      addFlags,
		SetupCmd: setupCmd,
		AddCmd:   addCmd,
	}
}
