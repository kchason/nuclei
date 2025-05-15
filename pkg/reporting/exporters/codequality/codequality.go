package codequality

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"

	"github.com/pkg/errors"
)

// Record is based off the required fields from https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
type Record struct {
	description string
	checkName   string `yaml:"check_name"`
	fingerprint string
	severity    string
	path        string `yaml:"location.path"`
	lineNumber  int    `yaml:"location.lines.begin"`
}

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []Record
}

// Options contains the configuration options for CodeQuality exporter client
// https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md#data-types which is targeted at integration
// with GitLab's CodeQuality https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
type Options struct {
	// File is the file to export the report to
	File string `yaml:"file"`
}

func GenerateFingerprint(event *output.ResultEvent) (string, error) {
	// Generates a UUID for the unique fingerprint
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	hasher := sha1.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)
	return hex.EncodeToString(sum), nil
}

// New creates a new exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []Record{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
// the resulting CodeQuality JSON file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Create a CodeQuality struct from the event
	lineNumber := 1
	if len(event.Lines) > 0 {
		lineNumber = event.Lines[0]
	}

	fingerprint, err := GenerateFingerprint(event)
	if err != nil {
		gologger.Warning().Msgf("failed to generate fingerprint, falling back to placeholder: %s", err)
		fingerprint = "Nuclei Scan Result"
	}

	record := Record{
		description: event.Info.Description,
		checkName:   event.Info.Name,
		fingerprint: fingerprint,
		severity:    event.Info.SeverityHolder.Severity.String(),
		path:        event.Path,
		lineNumber:  lineNumber,
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, record)

	return nil
}

// Close writes the in-memory data to the CodeQuality JSON file specified by
// options.CodeQuality and closes the exporter after operation
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Convert the rows to JSON byte array
	obj, err := json.Marshal(exporter.rows)
	if err != nil {
		return errors.Wrap(err, "failed to generate CodeQuality report")
	}

	// Attempt to write the JSON to file specified in options.CodeQuality
	if err := os.WriteFile(exporter.options.File, obj, 0644); err != nil {
		return errors.Wrap(err, "failed to create CodeQuality file")
	}

	return nil
}
