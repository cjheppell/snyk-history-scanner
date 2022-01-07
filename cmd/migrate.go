package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cjheppell/snyk-history-scanner/pkg/github"
	"github.com/cjheppell/snyk-history-scanner/pkg/snyk"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type migrateOpts struct {
	debug       bool
	snykToken   string
	productName string
	snykOrg     string
	githubToken string
	githubOwner string
	githubRepo  string
}

var migrateOptions = migrateOpts{}

func GetMigrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Used to migrate snyk-history-scanner snyk projects over to the native snyk version scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			if migrateOptions.debug {
				log.SetLevel(log.DebugLevel)
			}
			return doMigrate(migrateOptions)
		},
	}
	cmd.Flags().StringVar(&migrateOptions.productName, "product", "", "the name of the product being scanned")
	cmd.Flags().StringVar(&migrateOptions.snykOrg, "org", "", "the snyk organisation where existing snyk-history-scanner results reside")
	cmd.Flags().StringVar(&migrateOptions.snykToken, "snykToken", "", "the snyk access token to use for accessing the Snyk API")

	cmd.Flags().StringVar(&migrateOptions.githubToken, "githubToken", "", "the api token used for accessing the github api on behalf of the executing user")
	cmd.Flags().StringVar(&migrateOptions.githubOwner, "githubOwner", "", "the owner of the github repo associated with this Snyk project")
	cmd.Flags().StringVar(&migrateOptions.githubRepo, "githubRepo", "", "the github repo associated with this Snyk project")

	cmd.MarkFlagRequired("product")
	cmd.MarkFlagRequired("org")
	cmd.MarkFlagRequired("snykToken")

	cmd.MarkFlagRequired("githubToken")
	cmd.MarkFlagRequired("githubOwner")
	cmd.MarkFlagRequired("githubRepo")

	return cmd
}

func doMigrate(options migrateOpts) error {
	snykClient := snyk.NewApiClient(options.snykToken)
	githubClient, err := github.NewClient(options.githubToken)
	if err != nil {
		return err
	}

	projects, err := snykClient.ListProjectsInOrg(options.snykOrg)
	if err != nil {
		return err
	}

	tags, err := githubClient.ListTags(options.githubOwner, options.githubRepo)
	if err != nil {
		return err
	}

	snykProjectToTagMap := map[snyk.SnykApiProject]github.Tag{}

	for _, p := range projects {
		match := findMatch(tags, p, options.productName)
		if match == nil {
			fmt.Printf("couldnt find matching github tag for Snyk project '%s'. You'll need to add this one manually\n", p.Name)
			continue
		} else {
			snykProjectToTagMap[p] = *match
		}
	}

	fmt.Println("")
	fmt.Println("mapping generated:")
	for k, v := range snykProjectToTagMap {
		fmt.Printf("[%s] -> %s\n", k.Name, v.Name)
	}

	fmt.Println("")
	fmt.Printf("We'll now automatically checkout each of the specified tags, and run the command `snyk monitor --project %s --target-reference <TAG_VERSION> --all-projects --org %s`\n\n", options.productName, options.snykOrg)
	fmt.Print("Are you happy with the mapping of Snyk projects to github tags and want to run the above command for each tag [y/n]? ")
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(text) != "y" {
		fmt.Println("aborting - 'y' was not specified")
		return nil
	}

	// do the work

	return nil
}

func findMatch(tags []github.Tag, p snyk.SnykApiProject, productName string) *github.Tag {
	tagToFind := strings.TrimPrefix(p.Name, fmt.Sprintf("%s@", productName))
	var bestMatch *github.Tag
	for _, t := range tags {
		// prefer shortest tag names
		isBetterMatch := bestMatch == nil || len(t.Name) < len(bestMatch.Name)
		if strings.Contains(t.Name, tagToFind) && isBetterMatch {
			tag := t
			bestMatch = &tag
		}
	}
	return bestMatch
}
