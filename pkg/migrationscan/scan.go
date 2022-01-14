package migrationscan

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
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
		fmt.Println()

		fmt.Printf("running prescan work...\n")
		err = preScan(dir)
		if err != nil {
			return err
		}
		fmt.Println()

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

func preScan(repoRoot string) error {
	var mvnExists, dotnetExists bool
	_, err := exec.LookPath("mvn")
	if err != nil {
		fmt.Println("could not find mvn on the PATH, will not attempt to build Java projects")
	}
	mvnExists = err == nil

	_, err = exec.LookPath("dotnet")
	if err != nil {
		fmt.Println("could not find mvn on the PATH, will not attempt to build dotnet projects")
	}
	dotnetExists = err == nil

	if mvnExists {
		return mvnInstall(repoRoot)
	}

	if dotnetExists {
		return dotnetRestore(repoRoot)
	}

	return nil
}

func dotnetRestore(repoRoot string) error {
	fmt.Println("enumerating .sln's and .csproj's to issue dotnet restore's before running Snyk scan")
	return filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		isCsProjOrSln := strings.HasSuffix(d.Name(), ".sln") || strings.HasSuffix(d.Name(), ".csproj")
		if !d.IsDir() && isCsProjOrSln {
			folder := filepath.Dir(path)

			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			err = os.Chdir(folder)
			if err != nil {
				return err
			}
			defer func() {
				os.Chdir(wd)
			}()

			fmt.Printf("running dotnet restore for file %s\n", path)
			cmd := exec.Command("dotnet", "restore", "--interactive", "--ignore-failed-sources")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				fmt.Printf("dotnet restore failed for file: %s", path)
			}
		}
		return nil
	})
}

func mvnInstall(repoRoot string) error {
	fmt.Println("enumerating pom.xml's to issue mvn install's before running Snyk scan")
	return filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		isPomXml := strings.HasSuffix(d.Name(), "pom.xml")
		if !d.IsDir() && isPomXml {
			folder := filepath.Dir(path)

			wd, err := os.Getwd()
			if err != nil {
				return err
			}
			err = os.Chdir(folder)
			if err != nil {
				return err
			}
			defer func() {
				os.Chdir(wd)
			}()

			fmt.Printf("running mvn install for file %s\n", path)
			cmd := exec.Command("mvn", "install")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				fmt.Printf("mvn install failed for file: %s", path)
			}
		}
		return nil
	})
}
