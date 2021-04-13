package main

import (
	"log"

	"github.com/cjheppell/snyk-history-scanner/cmd"
)

func main() {
	rootCmd := cmd.GetRootCommand()
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
