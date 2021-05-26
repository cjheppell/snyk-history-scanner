package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestFileExclusionsOnlyExcludeFile_NotContainingDirectory(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("couldnt get working dir: %s", err)
	}

	subdir := filepath.Join(workingDir, "sub1")

	err = os.Mkdir(subdir, 0755)
	if err != nil {
		t.Fatalf("couldnt create subdir: %s", err)
	}
	defer func() {
		os.RemoveAll(subdir)
	}()

	_, err = os.Create(filepath.Join(subdir, "package.json"))
	if err != nil {
		t.Fatalf("couldnt create package.json in subdir: %s", err)
	}
	yarnLockPath := filepath.Join(subdir, "yarn.lock")
	_, err = os.Create(yarnLockPath)
	if err != nil {
		t.Fatalf("couldnt create yarn.lock in subdir: %s", err)
	}

	rootCmd := GetRootCommand()

	rootCmd.SetArgs([]string{"--product=foo", "--version=1", "--org=bar", "--exclude=package.json", "--snyk-cmd=true", "--npm", "--debug"})
	rootCmd.Execute()

	logOutput := buf.String()
	t.Log(logOutput)
	if !strings.Contains(logOutput, fmt.Sprintf("file '%s' was manifest match", yarnLockPath)) {
		t.Errorf("did not scan yarn lock, but should have done")
	}
}
