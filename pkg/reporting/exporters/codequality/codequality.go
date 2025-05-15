package codequality

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// CodeQualityRecord is based off the required fields from https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
type CodeQualityRecord struct {
	description string
	check_name  string
	fingerprint string
	severity    string
	location    struct {
		path  string
		lines struct {
			begin int
		}
	}
}

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []CodeQualityRecord
}

// Options contains the configuration options for CodeQuality exporter client
// https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md#data-types which is targeted at integration
// with GitLab's CodeQuality https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
type Options struct {
	// File is the file to export the report to
	File string `yaml:"file"`
}

// New creates a new exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []CodeQualityRecord{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
// the resulting CodeQuality JSON file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Create a CodeQuality struct from the event
	record := CodeQualityRecord{
		description: event.Info.Description,
		check_name: event.Info.Name,
		location: struct {
			path: event.Url,
			line: struct {
				begin: 1
			},
		},
		severity: event.Info.Severity,
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
