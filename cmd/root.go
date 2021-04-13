package cmd

import (
	"log"
	"os/exec"

	"github.com/spf13/cobra"
)

type options struct {
	dotnet bool
	golang bool
	java   bool
	npm    bool
}

func GetRootCommand() *cobra.Command {
	options := options{}
	cmd := &cobra.Command{
		Use:   "snyk-history-scanner",
		Short: "A very thin wrapper around the Snyk CLI tool to make it possible to monitor old releases of versions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return execute(options)
		},
	}
	cmd.PersistentFlags().BoolVar(&options.dotnet, "dotnet", false, "if dotnet projects should be scanned")
	cmd.PersistentFlags().BoolVar(&options.golang, "golang", false, "if golang projects should be scanned")
	cmd.PersistentFlags().BoolVar(&options.java, "java", false, "if java projects should be scanned")
	cmd.PersistentFlags().BoolVar(&options.npm, "npm", false, "if npm projects should be scanned")

	return cmd
}

func execute(options) error {
	_, err := exec.LookPath("snyk")
	if err != nil {
		log.Fatal("snyk is not available on the PATH")
	}

	return nil
}
