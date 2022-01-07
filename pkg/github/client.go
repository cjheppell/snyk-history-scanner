package github

import (
	"context"
	"net/http"

	"github.com/google/go-github/v39/github"
	"golang.org/x/oauth2"
)

type GithubClient struct {
	client *github.Client
}

func NewClient(token string) (*GithubClient, error) {
	var client *github.Client
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(context.TODO(), ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(http.DefaultClient)
	}

	return &GithubClient{
		client: client,
	}, nil
}

type Tag struct {
	Name   string `json:"name"`
	Commit commit `json:"commit"`
}

type commit struct {
	SHA string `json:"sha"`
}

func (c GithubClient) ListTags(owner, repoName string) ([]Tag, error) {
	listOpts := &github.ListOptions{
		PerPage: 30,
	}

	var allTags []*github.RepositoryTag

	for {
		tags, resp, err := c.client.Repositories.ListTags(context.TODO(), owner, repoName, listOpts)
		if err != nil {
			return nil, err
		}
		allTags = append(allTags, tags...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	var tags []Tag
	for _, t := range allTags {
		tags = append(tags, Tag{
			Name: *t.Name,
			Commit: commit{
				SHA: *t.Commit.SHA,
			},
		})
	}

	return tags, nil
}

func (c GithubClient) GetRepoUrl(owner, repoName string) (string, error) {
	r, _, err := c.client.Repositories.Get(context.TODO(), owner, repoName)
	if err != nil {
		return "", err
	}

	return r.GetCloneURL(), nil
}
