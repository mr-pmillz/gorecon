package recon

import (
	"fmt"
	"github.com/projectdiscovery/httpx/runner"
	"log"
	"math"

	"github.com/mr-pmillz/gorecon/localio"
)

// runHTTPX runs httpx against a slice of urls ...
func runHTTPX(urls []string, outputDir string) error {
	// write urls to file
	urlsFile := fmt.Sprintf("%s/all-urls.txt", outputDir)
	if err := localio.WriteLines(urls, urlsFile); err != nil {
		return localio.LogError(err)
	}
	var threads int
	threads = int(math.Round(float64(len(urls) / 2)))
	if threads > 50 {
		threads = 50
	}

	options := runner.Options{
		Methods:             "GET",
		InputFile:           urlsFile,
		RandomAgent:         true,
		FollowRedirects:     true,
		FollowHostRedirects: true,
		Location:            true,
		TechDetect:          true,
		Silent:              true,
		Output:              fmt.Sprintf("%s/httpx-output.txt", outputDir),
		OutputCDN:           true,
		OutputIP:            true,
		ExtractTitle:        true,
		StatusCode:          true,
		Debug:               false,
		DebugResponse:       false,
		DebugRequests:       false,
		NoColor:             false,
		ContentLength:       true,
		Threads:             threads,
		OutputServerHeader:  true,
		LeaveDefaultPorts:   true,
		Timeout:             30,
	}
	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		localio.LogFatal(err, "failed to create new httpx runner")
	}
	defer httpxRunner.Close()

	localio.PrintInfo("Httpx", "stdout", "Running httpx against enumerated hosts")
	httpxRunner.RunEnumeration()

	return nil
}

// runHTTPXOutputCSV runs httpx against a slice of urls ...
func runHTTPXOutputCSV(urls []string, outputDir string) (string, error) {
	// write urls to file
	urlsFile := fmt.Sprintf("%s/all-urls.txt", outputDir)
	if err := localio.WriteLines(urls, urlsFile); err != nil {
		return "", localio.LogError(err)
	}

	var threads int
	threads = int(math.Round(float64(len(urls) / 2)))
	if threads > 50 {
		threads = 50
	}
	resolvers := []string{
		"1.1.1.1",     // Cloudflare
		"1.0.0.1",     // Cloudflare Secondary
		"8.8.8.8",     // Google
		"8.8.4.4",     // Google Secondary
		"64.6.64.6",   // Verisign
		"64.6.65.6",   // Verisign Secondary
		"77.88.8.1",   // Yandex.DNS Secondary
		"74.82.42.42", // Hurricane Electric
	}

	options := runner.Options{
		Methods:             "GET",
		InputFile:           urlsFile,
		RandomAgent:         true,
		FollowRedirects:     true,
		FollowHostRedirects: true,
		Location:            true,
		TechDetect:          true,
		Silent:              true,
		Output:              fmt.Sprintf("%s/httpx-output.csv", outputDir),
		CSVOutput:           true,
		OutputCDN:           true,
		OutputIP:            true,
		ExtractTitle:        true,
		StatusCode:          true,
		Debug:               false,
		DebugResponse:       false,
		DebugRequests:       false,
		NoColor:             true,
		ContentLength:       true,
		Threads:             threads,
		OutputServerHeader:  true,
		LeaveDefaultPorts:   true,
		OutputContentType:   true,
		OutputMethod:        true,
		OutputResponseTime:  true,
		OutputCName:         true,
		OutputLinesCount:    true,
		OutputWordsCount:    true,
		Timeout:             30,
		Resolvers:           resolvers,
	}
	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		localio.LogFatal(err, "failed to create new httpx runner csv output options")
	}
	defer httpxRunner.Close()

	localio.PrintInfo("Httpx", "CSV", "Httpx Generating CSV File")
	httpxRunner.RunEnumeration()

	return fmt.Sprintf("%s/httpx-output.csv", outputDir), nil
}
