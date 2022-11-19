package recon

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/types"
	"net/url"
)

// runKatana runs Katana against a list of urls in a file
func runKatana(urlsFile string, opts *Options) error {
	outOfScope, err := getOutOfScope(opts.OutOfScope)
	if err != nil {
		return localio.LogError(err)
	}

	urls, err := localio.ReadLines(urlsFile)
	if err != nil {
		return localio.LogError(err)
	}

	var reOutOfScope []string //nolint:prealloc
	for _, i := range outOfScope {
		reOutOfScope = append(reOutOfScope, fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?$", i))
	}

	for _, u := range urls {
		urlParts, err := url.Parse(u)
		if err != nil {
			return localio.LogError(err)
		}

		reInScope := []string{fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?$", urlParts.Host)}
		katanaOpts := types.Options{
			Scope:             reInScope,
			OutOfScope:        reOutOfScope,
			MaxDepth:          2,
			Timeout:           15,
			CrawlDuration:     15,
			OutputFile:        fmt.Sprintf("%s/katana-%s.txt", opts.Output, urlParts.Host),
			NoColors:          false,
			JSON:              false,
			Silent:            false,
			Verbose:           true,
			ScrapeJSResponses: true,
			Headless:          true,
			ShowBrowser:       false,
		}

		crawlerOpts, err := types.NewCrawlerOptions(&katanaOpts)
		if err != nil {
			return localio.LogError(err)
		}

		crawler, err := standard.New(crawlerOpts)
		if err != nil {
			return localio.LogError(err)
		}

		if err = crawler.Crawl(u); err != nil {
			return localio.LogError(err)
		}

		err = crawler.Close()
		if err != nil {
			return localio.LogError(err)
		}
	}
	return nil
}
