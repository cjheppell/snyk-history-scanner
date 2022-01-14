package migrationscan

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cjheppell/snyk-history-scanner/pkg/github"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

func DoScanMultiple(productName, snykOrgName, snykToken, repoUrl, githubToken, githubUsername string, tags []github.Tag) error {
	currentWd, err := os.Getwd()
	if err != nil {
		return err
	}
	defer func() {
		os.Chdir(currentWd)
	}()

	dir, err := os.MkdirTemp("", "snyk-history-scanner*")
	if err != nil {
		return err
	}
	defer func() {
		os.RemoveAll(dir)
	}()

	fmt.Printf("cloning directory to %s, please wait...\n", dir)
	repo, err := cloneToDir(githubToken, githubUsername, dir, repoUrl)
	if err != nil {
		return fmt.Errorf("failed to clone github dir: %s", err)
	}

	err = os.Chdir(dir)
	if err != nil {
		return err
	}

	for _, tag := range tags {
		fmt.Printf("checking out tag %s...\n", tag.Name)
		err = checkoutHash(githubToken, githubUsername, repo, tag.Commit.SHA)
		if err != nil {
			return err
		}

		err = runSnykMonitor(tag.Name, productName, snykOrgName, snykToken)
		if err != nil {
			return fmt.Errorf("failed to run snyk monitor: %s", err)
		}

		err = gitClean(repo)
		if err != nil {
			return fmt.Errorf("failed to clean local worktree: %s", err)
		}

		// stop at the first for now
		break
	}

	return nil
}

func cloneToDir(token, username, cloneDir, repoUrl string) (*git.Repository, error) {
	httpAuth := &http.BasicAuth{
		Username: username,
		Password: token,
	}

	repo, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:   repoUrl,
		Auth:  httpAuth,
		Depth: 1,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to plainclone github remote: %s", err)
	}

	return repo, nil
}

func checkoutHash(token, username string, repo *git.Repository, hash string) error {
	httpAuth := &http.BasicAuth{
		Username: username,
		Password: token,
	}

	err := repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{"+refs/pull/*:refs/remotes/origin/pull/*"},
		Auth:     httpAuth,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch additional refspecs: %s", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree for repository: %s", err)
	}

	resolvedHash, err := repo.ResolveRevision(plumbing.Revision(hash))
	if err != nil {
		return fmt.Errorf("failed to convert %q to a valid hash: %s", hash, err)
	}

	err = worktree.Checkout(&git.CheckoutOptions{Hash: *resolvedHash})
	if err != nil {
		return fmt.Errorf("failed to checkout worktree: %s", err)
	}

	return nil
}

func gitClean(repo *git.Repository) error {
	worktree, err := repo.Worktree()
	if err != nil {
		return err
	}

	return worktree.Clean(&git.CleanOptions{
		Dir: true,
	})
}

func runSnykMonitor(tagVersion, productName, snykOrg, snykToken string) error {
	args := []string{"monitor", fmt.Sprintf("--org=%s", snykOrg), fmt.Sprintf("--target-reference=%s", tagVersion), "--all-projects"}

	fmt.Printf("running snyk %s\n", strings.Join(args, " "))

	cmd := exec.Command("snyk", args...)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SNYK_TOKEN=%s", snykToken))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}
