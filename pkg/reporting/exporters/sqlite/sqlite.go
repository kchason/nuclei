package sqlite

import (
	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

// Export appends the passed result event to the list of objects to be exported to the resulting SQLite file
func (exporter *Exporter) Export(event *output.ResultEvent) error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// If the IncludeRawPayload is not set, then set the request and response to an empty string in the event to avoid
	// writing them to the list of events.
	// This will reduce the amount of storage as well as the fields being excluded from the resulting SQLite output since
	// the property is set to "omitempty"
	if !exporter.options.IncludeRawPayload {
		event.Request = ""
		event.Response = ""
	}

	// Add the event to the rows
	exporter.rows = append(exporter.rows, *event)

	return nil
}

// Close writes the in-memory data to the SQLite file specified by options.SQLiteExport
func (exporter *Exporter) Close() error {
	exporter.mutex.Lock()
	defer exporter.mutex.Unlock()

	// Open the file for writing
	db, err := gorm.Open(sqlite.Open(exporter.options.File), &gorm.Config{})
	if err != nil {
		return errors.Wrap(err, "could not open sqlite file")
	}

	// Migrate the structure to conform with the output.ResultEvent struct
	err = db.AutoMigrate(&output.ResultEvent{})
	if err != nil {
		return err
	}

	// Loop through and insert each record into the database
	for _, row := range exporter.rows {
		db.Create(&row)
	}

	return nil
}
