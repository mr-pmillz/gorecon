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
		if err = localio.WriteStructToJSONFile(pubGitInfo, fmt.Sprintf("%s/company-repos/public-organization-gitinfo.json", opts.Output)); err != nil {
			return localio.LogError(err)
		}

		// runGitLeaks
		localio.PrintInfo("GitLeaks", fmt.Sprintf("Running GitLeaks against %s", opts.Company), fmt.Sprintf("found: %d public organization repositories", len(pubGitInfo.orgHTTPSCloneURLs)))
		if err = runGitLeaks(pubGitInfo.orgHTTPSCloneURLs, opts); err != nil {
			return localio.LogError(err)
		}

		// ToDo: Run against all Organization Users, Might take a while. Make this optional.. ToDo
		// Uncomment this line to do just that
		// localio.PrintInfo("GitLeaks", fmt.Sprintf("Running GitLeaks against all %s users!", opts.Company), fmt.Sprintf("found: %d public organization repositories", len(pubGitInfo.orgHTTPSCloneURLs)))
		// if err = runGitLeaks(pubGitInfo.orgUserHTTPSCloneURLs, opts); err != nil {
		//	 return localio.LogError(err)
		// }
	}
	return nil
}
