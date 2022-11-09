package srctleaks

import (
	"context"
	"fmt"
	"github.com/google/go-github/v48/github"
	"github.com/jpillora/go-tld"
	"github.com/mr-pmillz/gorecon/localio"
	"golang.org/x/oauth2"
	"reflect"
	"strings"
)

type GitHubClient struct {
	Client *github.Client
}

// newClient creates a new GitHub client for go-github module
func newClient(opts *Options) *GitHubClient {
	c := &GitHubClient{}
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: opts.GithubToken})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	c.Client = client
	return c
}

type PublicGitInfo struct {
	orgHTTPSCloneURLs     []string
	orgUserHTTPSCloneURLs []string
	Members               PublicGitMembers
}

type PublicGitMembers struct {
	GitHubProfileURL []string
	LoginName        []string
}

// GetPublicRepoURLs returns a slice of public repo URLs
func (c *GitHubClient) GetPublicRepoURLs(organization string) (*PublicGitInfo, error) {
	p := &PublicGitInfo{}
	repos, err := c.ListPublicOrgRepos(organization)
	if err != nil {
		return nil, localio.LogError(err)
	}
	var repoURLs []string
	for _, repo := range repos {
		repoURLs = append(repoURLs, *repo.CloneURL)
		p.orgHTTPSCloneURLs = append(p.orgHTTPSCloneURLs, *repo.CloneURL)
	}
	return p, nil
}

func (c *GitHubClient) ListPublicUserRepos(username string) ([]*github.Repository, error) {
	githubOpts := &github.RepositoryListOptions{
		Type:        "public",
		ListOptions: github.ListOptions{PerPage: 10},
	}
	var allRepos []*github.Repository
	for {
		repos, resp, err := c.Client.Repositories.List(context.Background(), username, githubOpts)
		if err != nil {
			return nil, localio.LogError(err)
		}
		if resp.TokenExpiration.IsZero() {
			localio.LogInfo("TokenExpired", resp.TokenExpiration.String(), "GitHub Personal Access Token is Expired...")
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		githubOpts.Page = resp.NextPage
	}

	return allRepos, nil
}

func (c *GitHubClient) ListPublicOrgRepos(organization string) ([]*github.Repository, error) {
	githubOpts := &github.RepositoryListByOrgOptions{
		Type:        "public",
		ListOptions: github.ListOptions{PerPage: 10},
	}
	var allRepos []*github.Repository
	for {
		repos, resp, err := c.Client.Repositories.ListByOrg(context.Background(), organization, githubOpts)
		if err != nil {
			return nil, localio.LogError(err)
		}
		if resp.TokenExpiration.IsZero() {
			localio.LogInfo("TokenExpired", resp.TokenExpiration.String(), "GitHub Personal Access Token is Expired...")
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		githubOpts.Page = resp.NextPage
	}

	return allRepos, nil
}

// SearchUsers searches GitHub for the supplied Company arg for the organization user and returns the best match based on the primary company base domain.
// and compares it against the GitHub username which is often similar or the same as the base domain minus tld.
func (c *GitHubClient) SearchUsers(opts *Options) (string, error) {
	var baseDomains []string
	rtd := reflect.TypeOf(opts.Domain)
	switch rtd.Kind() {
	case reflect.Slice:
		for _, d := range opts.Domain.([]string) {
			baseDomain, _ := tld.Parse(fmt.Sprintf("https://%s", d))
			baseDomains = append(baseDomains, baseDomain.Domain)
			baseDomains = append(baseDomains, strings.ReplaceAll(baseDomain.Domain, "-", ""))
		}
	case reflect.String:
		baseDomain, _ := tld.Parse(fmt.Sprintf("https://%s", opts.Domain.(string)))
		baseDomains = append(baseDomains, baseDomain.Domain)
		baseDomains = append(baseDomains, strings.ReplaceAll(baseDomain.Domain, "-", ""))
	}

	var matchedUsers []string
	users, resp, err := c.Client.Search.Users(context.Background(), opts.Company, nil)
	if err != nil {
		return "", localio.LogError(err)
	}
	if resp.TokenExpiration.IsZero() {
		localio.LogInfo("TokenExpired", resp.TokenExpiration.String(), "GitHub Personal Access Token is Expired...")
	}

	for _, user := range users.Users {
		if *user.Type == "Organization" && localio.Contains(baseDomains, *user.Login) {
			matchedUsers = append(matchedUsers, *user.Login)
		}
	}

	if len(matchedUsers) >= 1 {
		localio.LogInfo("GitHub Organization", matchedUsers[0], "Found Public GitHub Organization!")
		return matchedUsers[0], nil
	}

	return "", nil
}

// GetPublicOrgMembers ...
func GetPublicOrgMembers(users []*github.User) []string {
	var orgUsers []string
	for _, user := range users {
		orgUsers = append(orgUsers, *user.Login)
	}
	return orgUsers
}

func (c *GitHubClient) ListPublicMembers(organization string) ([]*github.User, error) {
	memberOpts := github.ListMembersOptions{
		PublicOnly: true,
		ListOptions: github.ListOptions{
			PerPage: 10,
		},
	}

	var allMembers []*github.User
	for {
		members, resp, err := c.Client.Organizations.ListMembers(context.Background(), organization, &memberOpts)
		if err != nil {
			return nil, localio.LogError(err)
		}
		if resp.TokenExpiration.IsZero() {
			localio.LogInfo("TokenExpired", resp.TokenExpiration.String(), "GitHub Personal Access Token is Expired...")
		}
		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
	}
	return allMembers, nil
}
