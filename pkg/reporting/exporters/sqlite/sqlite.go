package sqlite

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"sync"
)

type Exporter struct {
	options *Options
	mutex   *sync.Mutex
	rows    []output.ResultEvent
}

// Options contains the configuration options for SQLite exporter client
type Options struct {
	// File is the file to export found SQLite result to
	File              string `yaml:"file"`
	IncludeRawPayload bool   `yaml:"include-raw-payload"`
}

// New creates a new SQLite exporter integration client based on options.
func New(options *Options) (*Exporter, error) {
	exporter := &Exporter{
		mutex:   &sync.Mutex{},
		options: options,
		rows:    []output.ResultEvent{},
	}
	return exporter, nil
}

func (exporter *Exporter) Export(event *output.ResultEvent) error {
	// TODO: implement
}

func (exporter *Exporter) Close() error {
	// TODO: implement
}
