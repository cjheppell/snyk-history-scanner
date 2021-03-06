package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cjheppell/snyk-history-scanner/pkg"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type options struct {
	dotnet         bool
	golang         bool
	java           bool
	javascript     bool
	exclusions     []string
	snykOrg        string
	productName    string
	productVersion string
	snykCmd        string
	debug          bool
}

var opts = options{}

var defaultDirExcludes = []string{
	"node_modules",
	".git",
}

func GetRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snyk-history-scanner",
		Short: "A very thin wrapper around the Snyk CLI tool to make it possible to monitor old releases of versions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.debug {
				log.SetLevel(log.DebugLevel)
			}
			return execute(opts, args)
		},
	}
	cmd.Flags().StringVar(&opts.productName, "product", "", "the name of the product being scanned")
	cmd.Flags().StringVar(&opts.productVersion, "version", "", "the version of the product being scanned")
	cmd.Flags().StringVar(&opts.snykOrg, "org", "", "the snyk organisation this scan should be a part of")
	cmd.MarkFlagRequired("product")
	cmd.MarkFlagRequired("version")
	cmd.MarkFlagRequired("org")

	cmd.Flags().BoolVar(&opts.dotnet, "dotnet", false, "if dotnet projects should be scanned")
	cmd.Flags().BoolVar(&opts.golang, "golang", false, "if golang projects should be scanned")
	cmd.Flags().BoolVar(&opts.java, "java", false, "if java projects should be scanned")
	cmd.Flags().BoolVar(&opts.javascript, "npm", false, "if npm projects should be scanned")
	cmd.Flags().StringSliceVar(&opts.exclusions, "exclude", []string{}, "pass --exclude multiple times to exclude these directories/files (must be relative to where you're running this cli from)")
	cmd.Flags().StringVar(&opts.snykCmd, "snyk-cmd", "snyk", "the command to run Snyk, i.e. 'npx snyk'")
	cmd.Flags().BoolVar(&opts.debug, "debug", false, "run in debug mode")

	return cmd
}

func execute(opts options, snykArgs []string) error {
	exclusions := defaultDirExcludes
	exclusions = append(exclusions, opts.exclusions...)
	manifests := getManifests(opts)
	cmdFields := strings.Fields(opts.snykCmd)
	cmd := cmdFields[0]
	cmdArgs := cmdFields[1:]

	_, err := exec.LookPath(cmd)
	if err != nil {
		return err
	}
	log.Debugf("found '%s' on path", cmd)

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	log.Debugf("working dir is '%s'", workingDir)

	err = filepath.Walk(workingDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if in(info.Name(), exclusions) {
				if info.IsDir() {
					log.Debugf("skipping directory '%s' as it is excluded", path)
					return filepath.SkipDir
				}
				log.Debugf("skipping file '%s' as it is excluded", path)
				return nil
			}

			log.Debugf("inspecting file '%s'", path)

			if isManifestMatch(info.Name(), manifests) {
				fmt.Printf("scanning '%s' with snyk...\n", path)
				log.Debugf("file '%s' was manifest match", path)
				manifestRelativePath := getManifestRelativePath(workingDir, path)
				err := runSnykMonitor(manifestRelativePath, opts.productName, manifestRelativePath, opts.productVersion, opts.snykOrg, cmd, cmdArgs, snykArgs)
				if err != nil {
					return err
				}
				log.Debugf("successfully ran snyk monitor on file '%s'", path)
			}
			return nil
		})

	return err
}

func runSnykMonitor(file, productName, projectName, version, snykOrg string, snykCmd string, cmdArgs []string, extraArgs []string) error {
	args := []string{"monitor", fmt.Sprintf("--file=%s", file), fmt.Sprintf("--project-name=%s@%s", projectName, version), fmt.Sprintf("--remote-repo-url=%s@%s", productName, version), fmt.Sprintf("--org=%s", snykOrg)}
	args = append(cmdArgs, args...)
	args = append(args, extraArgs...)

	fmt.Printf("running '%s %s'\n", snykCmd, strings.Join(args, " "))

	cmd := exec.Command(snykCmd, args...)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(string(output))
		return err
	}
	fmt.Println(string(output))
	log.Debug("finished running snyk")
	return nil
}

func isManifestMatch(filename string, manifests []string) bool {
	for _, manifest := range manifests {
		if strings.EqualFold(filename, manifest) {
			return true
		}
	}
	return false
}

func getManifestRelativePath(workingDir, fullPath string) string {
	return fullPath[len(workingDir)+1:]
}

func getManifests(opts options) []string {
	manifests := []string{}
	if opts.dotnet {
		manifests = append(manifests, pkg.DotnetManifests...)
	}
	if opts.java {
		manifests = append(manifests, pkg.JavaManifests...)
	}
	if opts.javascript {
		manifests = append(manifests, pkg.JavascriptManifests...)
	}
	if opts.golang {
		manifests = append(manifests, pkg.GolangManifests...)
	}
	return manifests
}

func in(needle string, haystack []string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
