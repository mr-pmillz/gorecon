package srctleaks

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
)

func Run(opts *Options) error {
	client := newClient(opts)
	organization, err := client.SearchUsers(opts)
	if err != nil {
		return localio.LogError(err)
	}
	if organization != "" {
		pubGitInfo, err := client.GetPublicOrgRepoURLs(organization)
		if err != nil {
			return localio.LogError(err)
		}

		members, err := client.GetPublicOrgMembers(organization)
		if err != nil {
			return localio.LogError(err)
		}
		pubGitInfo.Members = members.Members

		orgMemberRepoURLs, err := client.GetAllOrgMemberRepoURLs(pubGitInfo.Members.LoginName)
		if err != nil {
			return localio.LogError(err)
		}
		pubGitInfo.orgUserHTTPSCloneURLs = orgMemberRepoURLs.orgUserHTTPSCloneURLs

		// write found data to json file
		if err = localio.WriteStructToJSONFile(pubGitInfo, fmt.Sprintf("%s/public-organization-gitinfo.json", opts.Output)); err != nil {
			return localio.LogError(err)
		}

		// runGitLeaks
		localio.LogInfo("GitLeaks", "Running GitLeaks", fmt.Sprintf("found: %d organization repositories", len(pubGitInfo.orgHTTPSCloneURLs)))
		if err = runGitLeaks(pubGitInfo.orgHTTPSCloneURLs, opts); err != nil {
			return localio.LogError(err)
		}
	}
	return nil
}
