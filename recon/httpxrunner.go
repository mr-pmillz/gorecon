package recon

import (
	"fmt"
	"github.com/projectdiscovery/httpx/runner"
	"log"

	"github.com/mr-pmillz/gorecon/localio"
)

// runHTTPX runs httpx against a slice of urls ...
func runHTTPX(urls []string, outputDir string) error {
	// write urls to file
	urlsFile := fmt.Sprintf("%s/all-urls.txt", outputDir)
	if err := localio.WriteLines(urls, urlsFile); err != nil {
		return localio.LogError(err)
	}

	options := runner.Options{
		Methods:            "GET",
		InputFile:          urlsFile,
		RandomAgent:        true,
		FollowRedirects:    true,
		Location:           true,
		TechDetect:         true,
		Silent:             true,
		Output:             fmt.Sprintf("%s/httpx-output.txt", outputDir),
		OutputCDN:          true,
		OutputIP:           true,
		ExtractTitle:       true,
		StatusCode:         true,
		Debug:              false,
		DebugResponse:      false,
		DebugRequests:      false,
		NoColor:            false,
		ContentLength:      true,
		Threads:            20,
		OutputServerHeader: true,
		LeaveDefaultPorts:  true,
		Timeout:            30,
	}
	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal()
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

	options := runner.Options{
		Methods:            "GET",
		InputFile:          urlsFile,
		RandomAgent:        true,
		FollowRedirects:    true,
		Location:           true,
		TechDetect:         true,
		Silent:             true,
		Output:             fmt.Sprintf("%s/httpx-output.csv", outputDir),
		CSVOutput:          true,
		OutputCDN:          true,
		OutputIP:           true,
		ExtractTitle:       true,
		StatusCode:         true,
		Debug:              false,
		DebugResponse:      false,
		DebugRequests:      false,
		NoColor:            true,
		ContentLength:      true,
		Threads:            20,
		OutputServerHeader: true,
		LeaveDefaultPorts:  true,
		OutputContentType:  true,
		OutputMethod:       true,
		OutputResponseTime: true,
		OutputCName:        true,
		OutputLinesCount:   true,
		OutputWordsCount:   true,
		Asn:                true,
		Timeout:            60,
	}
	if err := options.ValidateOptions(); err != nil {
		log.Fatal(err)
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		log.Fatal()
	}
	defer httpxRunner.Close()

	localio.PrintInfo("Httpx", "CSV", "Httpx Generating CSV File")
	httpxRunner.RunEnumeration()

	return fmt.Sprintf("%s/httpx-output.csv", outputDir), nil
}
