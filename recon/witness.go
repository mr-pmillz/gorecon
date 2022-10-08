package recon

import (
	"fmt"
	"github.com/mr-pmillz/gorecon/localio"
	"os"
)

// runGoWitness installs the latest version and runs goWitness
func runGoWitness(httpxCSV, outputDir string) error {
	// install the latest version of goWitness
	if err := localio.RunCommandPipeOutput("go install github.com/sensepost/gowitness@latest"); err != nil {
		return err
	}
	if gowitness, exists := localio.CommandExists("gowitness"); exists {
		urlFile, err := WriteHttpxURLsToFile(httpxCSV, outputDir)
		if err != nil {
			return err
		}
		goWitnessDir := fmt.Sprintf("%s/gowitness", outputDir)
		goWitnessDB := fmt.Sprintf("%s/gowitness/gowitness.sqlite3", outputDir)
		goWitnessReport := fmt.Sprintf("%s/gowitness/report.html", outputDir)

		if err = os.MkdirAll(goWitnessDir, os.ModePerm); err != nil {
			return err
		}

		if err = localio.RunCommandPipeOutput(fmt.Sprintf("%s file -f %s --screenshot-path %s --db-path %s -t 20", gowitness, urlFile, goWitnessDir, goWitnessDB)); err != nil {
			return err
		}

		if err = localio.RunCommandPipeOutput(fmt.Sprintf("%s report export --db-path %s --file %s --screenshot-path %s", gowitness, goWitnessDB, goWitnessReport, goWitnessDir)); err != nil {
			return err
		}

		localio.PrintInfo("Gowitness", fmt.Sprintf("%s server -A --db-path %s --screenshot-path %s", gowitness, goWitnessDB, goWitnessDir), "To run the gowitness server, run the following command:")
	}

	return nil
}
