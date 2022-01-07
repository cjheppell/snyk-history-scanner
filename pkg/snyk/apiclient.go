package snyk

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ApiClient struct {
	token string
}

const snykApiEndpoint = "https://snyk.io/api/v1"

func NewApiClient(token string) ApiClient {
	return ApiClient{
		token: token,
	}
}

type snykApiListProjectsResp struct {
	Projects []SnykApiProject `json:"projects"`
}

type SnykApiProject struct {
	Name string `json:"remoteRepoUrl"`
	Id   string `json:"id"`
}

func (c ApiClient) ListProjectsInOrg(org string) ([]SnykApiProject, error) {
	request, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/org/%s/projects", snykApiEndpoint, org), nil)
	if err != nil {
		return nil, err
	}

	c.addAuthHeader(request)

	res, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list requests, unexpected status code: %d", res.StatusCode)
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var apiResp snykApiListProjectsResp

	err = json.Unmarshal(bodyBytes, &apiResp)
	if err != nil {
		return nil, err
	}

	projectsRecorded := map[string]bool{}
	var uniqueProjects []SnykApiProject
	for _, p := range apiResp.Projects {
		if _, seen := projectsRecorded[p.Name]; seen {
			continue
		}
		uniqueProjects = append(uniqueProjects, p)
		projectsRecorded[p.Name] = true
	}

	return uniqueProjects, nil
}

func (c ApiClient) addAuthHeader(req *http.Request) {
	req.Header.Add("Authorization", fmt.Sprintf("token %s", c.token))
}
