package recon

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/v2/localio"
	"net/url"
	"strings"
)

// runKatana ...
func runKatana(urlsFile string, opts *Options) error {
	if err := localio.RunCommandPipeOutput("GO111MODULE=on go install github.com/projectdiscovery/katana/cmd/katana@latest"); err != nil {
		return err
	}

	urls, err := localio.ReadLines(urlsFile)
	if err != nil {
		return localio.LogError(err)
	}
	ignoreRegex := "(.+)(\\.css\\?.*|[\\.js]\\?.*|assets\\/.*|images\\/.*|img\\/.*|static\\/.*|\\.js|\\.css)"

	if katanaBin, exists := localio.CommandExists("katana"); exists {
		for _, u := range urls {
			urlParts, err := url.Parse(u)
			if err != nil {
				localio.LogWarningf("URL invalid: %s", u)
				continue
			}
			outputFile := fmt.Sprintf("%s/katana-%s.txt", opts.Output, strings.Split(urlParts.Host, ":")[0])
			command := fmt.Sprintf("%s -u %s -jc -v -hl -nos -c 40 -p 40 -ef png,css,svg,js,jpg -cos '%s' -o %s", katanaBin, u, ignoreRegex, outputFile)
			if err = localio.RunCommandPipeOutput(command); err != nil {
				return localio.LogError(err)
			}
		}
	}

	return nil
}

// TODO: Run natively as pkg, v0.0.2 seems to have context issues or idk how to resolve bug :)
// Project is relatively new, wait until potential bugs are resolved...
// Work around, just run it as the binary
// imports
// "github.com/projectdiscovery/katana/pkg/types"
// "github.com/projectdiscovery/katana/pkg/engine/hybrid"
// runKatanaNative runs Katana against a list of urls in a file

// func runKatanaNative(urlsFile string, opts *Options) error {
//	outOfScope, err := getOutOfScope(opts.OutOfScope)
//	if err != nil {
//		return localio.LogError(err)
//	}
//
//	urls, err := localio.ReadLines(urlsFile)
//	if err != nil {
//		return localio.LogError(err)
//	}
//
//	var reOutOfScope []string //nolint:prealloc
//	for _, i := range outOfScope {
//		outOfScopeRegex := strings.ReplaceAll(i, ".", "\\.")
//		outOfScopeRegex2 := strings.ReplaceAll(outOfScopeRegex, ":", "\\:")
//		reOutOfScope = append(reOutOfScope, fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?(\\/.*)?$", outOfScopeRegex2))
//	}
//
//	for _, u := range urls {
//		urlParts, err := url.Parse(u)
//		if err != nil {
//			return localio.LogError(err)
//		}
//
//		regexHost := strings.ReplaceAll(urlParts.Host, ".", "\\.")
//		regexHost2 := strings.ReplaceAll(regexHost, ":", "\\:")
//		urlInScope := fmt.Sprintf("^(http:\\/\\/|https:\\/\\/)+(%s)?(\\/.*)?$", regexHost2)
//		reInScope := []string{urlInScope}
//		katanaOpts := types.Options{
//			URLs:       []string{u},
//			Scope:      reInScope,
//			OutOfScope: reOutOfScope,
//			FieldScope: "rdn",
//			Strategy:   "depth-first",
//			MaxDepth:   2,
//			//Timeout:    15,
//			//CrawlDuration:     15,
//			OutputFile:        fmt.Sprintf("%s/katana-%s.txt", opts.Output, strings.Split(urlParts.Host, ":")[0]),
//			NoColors:          false,
//			JSON:              false,
//			Concurrency:       20,
//			Parallelism:       20,
//			Verbose:           true,
//			ScrapeJSResponses: true,
//			Headless:          true,
//			HeadlessNoSandbox: true,
//			ShowBrowser:       false,
//		}
//
//		crawlerOpts, err := types.NewCrawlerOptions(&katanaOpts)
//		if err != nil {
//			return localio.LogError(err)
//		}
//
//		crawler, err := hybrid.New(crawlerOpts)
//		if err != nil {
//			return localio.LogError(err)
//		}
//
//		localio.Infof("Running Katana against URL: %s", u)
//		if err := crawler.Crawl(u); err != nil {
//			return localio.LogError(err)
//		}
//
//		err = crawler.Close()
//		if err != nil {
//			return localio.LogError(err)
//		}
//	}
//	return nil
//}
