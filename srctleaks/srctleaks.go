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
		pubGitInfo.OrgUserHTTPSCloneURLs = orgMemberRepoURLs.OrgUserHTTPSCloneURLs
		pubGitInfo.OrgUserNonForkedHTTPSCloneURLs = orgMemberRepoURLs.OrgUserNonForkedHTTPSCloneURLs

		// write found data to json file
		if err = localio.WriteStructToJSONFile(pubGitInfo, fmt.Sprintf("%s/company-repos/public-organization-gitinfo.json", opts.Output)); err != nil {
			return localio.LogError(err)
		}

		// runGitLeaks
		localio.PrintInfo("GitLeaks", fmt.Sprintf("Running GitLeaks against %s", opts.Company), fmt.Sprintf("found: %d public organization repositories", len(pubGitInfo.OrgHTTPSCloneURLs)))
		if err = runGitLeaks(pubGitInfo.OrgHTTPSCloneURLs, opts); err != nil {
			return localio.LogError(err)
		}

		// if --check-all-org-users is true, run GitLeaks against all organization public member users own public NON-FORKED repos
		if opts.CheckAllOrgUsers {
			localio.PrintInfo("GitLeaks", fmt.Sprintf("Running GitLeaks against all %s users!", opts.Company), fmt.Sprintf("found: %d public organization repositories", len(pubGitInfo.OrgUserNonForkedHTTPSCloneURLs)))
			if err = runGitLeaks(pubGitInfo.OrgUserNonForkedHTTPSCloneURLs, opts); err != nil {
				return localio.LogError(err)
			}
		}
	}
	return nil
}
