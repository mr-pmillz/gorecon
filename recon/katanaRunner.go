package recon

import (
	"fmt"
)

// imports for katana once bug fixed.
//	"github.com/projectdiscovery/katana/pkg/engine/standard"
//	"github.com/projectdiscovery/katana/pkg/types"

func todo() {
	fmt.Println(`1awaiting fix for 
# github.com/projectdiscovery/subfinder/v2/pkg/subscraping
../../go/pkg/mod/github.com/projectdiscovery/subfinder/v2@v2.5.4/pkg/subscraping/agent.go:49:61: cannot use rateLimit (variable of type int) as type int64 in argument to ratelimit.New
`)
}

//// runKatana ...
//func runKatana(URLsFile string, opts *Options) error {
//	outOfScope, err := getOutOfScope(opts.OutOfScope)
//	if err != nil {
//		return localio.LogError(err)
//	}
//	urls, err := localio.ReadLines(URLsFile)
//	if err != nil {
//		return localio.LogError(err)
//	}
//	var reOutOfScope []string
//	for _, i := range outOfScope {
//		reOutOfScope = append(reOutOfScope, fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?$", i))
//	}
//	for _, u := range urls {
//		urlParts, err := url.Parse(u)
//		if err != nil {
//			return localio.LogError(err)
//		}
//		reInScope := []string{fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?$", urlParts.Host)}
//		crawler, err := standard.New(&types.CrawlerOptions{
//			Options: &types.Options{
//				Scope:             reInScope,
//				OutOfScope:        reOutOfScope,
//				MaxDepth:          2,
//				Timeout:           15,
//				CrawlDuration:     15,
//				OutputFile:        fmt.Sprintf("%s/katana-%s.txt", opts.Output, urlParts.Host),
//				NoColors:          false,
//				JSON:              false,
//				Silent:            false,
//				Verbose:           true,
//				ScrapeJSResponses: true,
//				Headless:          true,
//				ShowBrowser:       false,
//			},
//		})
//		if err = crawler.Crawl(u); err != nil {
//			return localio.LogError(err)
//		}
//	}
//	return nil
//}
