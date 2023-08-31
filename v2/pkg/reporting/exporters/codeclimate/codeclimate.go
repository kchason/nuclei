package codeclimate

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"sync"
)

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []output.ResultEvent
}

// Options contain the configuration options for CodeClimate exporter client
type Options struct {
	// File is the file to export the CodeClimate result file to
	File string `yaml:"file"`
}

// New creates a new CodeClimate exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

// Export appends the passed result event to the list of objects to be exported to
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	return nil
}

// Close writes the in-memory data to the CodeClimate file specified by options.CodeClimateExport
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// TODO

	return nil
}
