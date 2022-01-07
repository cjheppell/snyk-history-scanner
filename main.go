package main

import (
	"fmt"
	"os"

	"github.com/cjheppell/snyk-history-scanner/cmd"
)

func main() {
	rootCmd := cmd.GetRootCommand()
	rootCmd.AddCommand(cmd.GetMigrateCommand())
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
