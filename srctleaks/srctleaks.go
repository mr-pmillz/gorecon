package srctleaks

import "github.com/mr-pmillz/gorecon/localio"

func Run(opts *Options) error {
	client := newClient(opts)
	organization, err := client.SearchUsers(opts)
	if err != nil {
		return localio.LogError(err)
	}
	if organization != "" {
		pubGitInfo, err := client.GetPublicRepoURLs(organization)
		if err != nil {
			return localio.LogError(err)
		}

		members, err := client.ListPublicMembers(organization)
		if err != nil {
			return localio.LogError(err)
		}
		for _, member := range members {
			pubGitInfo.Members.LoginName = append(pubGitInfo.Members.LoginName, member.Login)
			pubGitInfo.Members.GitHubProfileURL = append(pubGitInfo.Members.GitHubProfileURL, member.HTMLURL)
		}
		if err = localio.PrettyPrint(pubGitInfo); err != nil {
			return err
		}
	}
	return nil
}
