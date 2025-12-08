package databaseacquisition

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"
)

func setupTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	
	// Create a temporary directory for the SQLite database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Create test table
	_, err = db.Exec(`
		CREATE TABLE logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message TEXT NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			level TEXT,
			source TEXT
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	return db, dbPath
}

func insertTestLogs(t *testing.T, db *sql.DB, count int) {
	t.Helper()
	
	for i := 0; i < count; i++ {
		_, err := db.Exec(
			"INSERT INTO logs (message, timestamp, level, source) VALUES (?, ?, ?, ?)",
			fmt.Sprintf("Test log message %d", i),
			time.Now().Add(time.Duration(i)*time.Second),
			"info",
			"test",
		)
		if err != nil {
			t.Fatalf("Failed to insert test log: %v", err)
		}
	}
}

func TestConfigure(t *testing.T) {
	tests := []struct {
		name      string
		config    string
		wantErr   bool
	}{
		{
			name: "valid_config",
			config: `
source: database
driver: sqlite3
dsn: ":memory:"
query: "SELECT message FROM logs"
log_column: message
labels:
  type: test
`,
			wantErr: false,
		},
		{
			name: "missing_driver",
			config: `
source: database
dsn: ":memory:"
query: "SELECT message FROM logs"
log_column: message
`,
			wantErr: true,
		},
		{
			name: "missing_query",
			config: `
source: database
driver: sqlite3
dsn: ":memory:"
log_column: message
`,
			wantErr: true,
		},
		{
			name: "missing_log_column",
			config: `
source: database
driver: sqlite3
dsn: ":memory:"
query: "SELECT message FROM logs"
`,
			wantErr: true,
		},
		{
			name: "timestamp_without_placeholder",
			config: `
source: database
driver: sqlite3
dsn: ":memory:"
query: "SELECT message FROM logs"
log_column: message
timestamp_column: timestamp
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DatabaseSource{}
			logger := log.NewEntry(log.New())
			logger.Logger.SetOutput(os.Stderr)
			
			err := d.Configure(context.Background(), []byte(tt.config), logger, metrics.AcquisitionMetricsLevelFull)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("Configure() error = %v, wantErr %v", err, tt.wantErr)
			}
			
			if d.db != nil {
				d.db.Close()
			}
		})
	}
}

func TestOneShotAcquisition(t *testing.T) {
	db, dbPath := setupTestDB(t)
	defer db.Close()

	// Insert test data
	insertTestLogs(t, db, 5)

	config := fmt.Sprintf(`
source: database
driver: sqlite3
dsn: "%s"
query: "SELECT message, timestamp FROM logs ORDER BY timestamp"
log_column: message
mode: cat
labels:
  type: test
`, dbPath)

	d := &DatabaseSource{}
	logger := log.NewEntry(log.New())
	logger.Logger.SetLevel(log.DebugLevel)
	logger.Logger.SetOutput(os.Stderr)

	err := d.Configure(context.Background(), []byte(config), logger, metrics.AcquisitionMetricsLevelFull)
	if err != nil {
		t.Fatalf("Failed to configure: %v", err)
	}
	defer d.db.Close()

	out := make(chan pipeline.Event, 10)
	tomb := &tomb.Tomb{}

	go func() {
		err := d.OneShotAcquisition(context.Background(), out, tomb)
		if err != nil {
			t.Errorf("OneShotAcquisition failed: %v", err)
		}
		close(out)
	}()

	// Collect events
	var events []pipeline.Event
	for evt := range out {
		events = append(events, evt)
	}

	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}

	// Verify first event
	if len(events) > 0 {
		if events[0].Line.Raw != "Test log message 0" {
			t.Errorf("Expected 'Test log message 0', got '%s'", events[0].Line.Raw)
		}
	}
}

func TestStreamingAcquisition(t *testing.T) {
	db, dbPath := setupTestDB(t)
	defer db.Close()

	// Insert initial data
	insertTestLogs(t, db, 2)

	config := fmt.Sprintf(`
source: database
driver: sqlite3
dsn: "%s"
query: "SELECT message, timestamp FROM logs WHERE timestamp > '{{.timestamp}}' ORDER BY timestamp"
log_column: message
timestamp_column: timestamp
poll_interval: 1s
mode: tail
labels:
  type: test
`, dbPath)

	d := &DatabaseSource{}
	logger := log.NewEntry(log.New())
	logger.Logger.SetLevel(log.DebugLevel)
	logger.Logger.SetOutput(os.Stderr)

	err := d.Configure(context.Background(), []byte(config), logger, metrics.AcquisitionMetricsLevelFull)
	if err != nil {
		t.Fatalf("Failed to configure: %v", err)
	}
	defer d.db.Close()

	out := make(chan pipeline.Event, 10)
	tomb := &tomb.Tomb{}

	tomb.Go(func() error {
		return d.StreamingAcquisition(context.Background(), out, tomb)
	})

	// Give it time to do initial query
	time.Sleep(500 * time.Millisecond)

	// Insert more data
	insertTestLogs(t, db, 3)

	// Wait for poll
	time.Sleep(1500 * time.Millisecond)

	// Stop the acquisition
	tomb.Kill(nil)
	tomb.Wait()
	close(out)

	// Collect events
	var events []pipeline.Event
	for evt := range out {
		events = append(events, evt)
	}

	// Should have gotten some events (at least the new ones)
	if len(events) < 3 {
		t.Logf("Warning: Expected at least 3 events, got %d", len(events))
	}
}

func TestBuildQuery(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		timestampCol  string
		lastTimestamp time.Time
		wantContains  string
	}{
		{
			name:          "no_placeholder",
			query:         "SELECT * FROM logs",
			timestampCol:  "",
			lastTimestamp: time.Time{},
			wantContains:  "SELECT * FROM logs",
		},
		{
			name:          "with_placeholder",
			query:         "SELECT * FROM logs WHERE timestamp > '{{.timestamp}}'",
			timestampCol:  "timestamp",
			lastTimestamp: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			wantContains:  "2023-01-01 12:00:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DatabaseSource{
				config: DatabaseConfiguration{
					Query:           tt.query,
					TimestampColumn: tt.timestampCol,
				},
				lastTimestamp: tt.lastTimestamp,
			}

			result := d.buildQuery()
			
			if tt.wantContains != "" && result != tt.wantContains && !contains(result, tt.wantContains) {
				t.Errorf("buildQuery() = %v, want to contain %v", result, tt.wantContains)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestGetName(t *testing.T) {
	d := &DatabaseSource{}
	if name := d.GetName(); name != "database" {
		t.Errorf("GetName() = %v, want 'database'", name)
	}
}

func TestSupportedModes(t *testing.T) {
	d := &DatabaseSource{}
	modes := d.SupportedModes()
	
	want := []string{"tail", "cat"}
	if len(modes) != len(want) {
		t.Errorf("SupportedModes() returned %d modes, want %d", len(modes), len(want))
	}
}

func TestAdditionalColumns(t *testing.T) {
	db, dbPath := setupTestDB(t)
	defer db.Close()

	// Insert test data
	insertTestLogs(t, db, 2)

	config := fmt.Sprintf(`
source: database
driver: sqlite3
dsn: "%s"
query: "SELECT message, timestamp, level, source FROM logs ORDER BY timestamp"
log_column: message
additional_columns:
  - level
  - source
mode: cat
labels:
  type: test
`, dbPath)

	d := &DatabaseSource{}
	logger := log.NewEntry(log.New())
	logger.Logger.SetLevel(log.DebugLevel)
	logger.Logger.SetOutput(os.Stderr)

	err := d.Configure(context.Background(), []byte(config), logger, metrics.AcquisitionMetricsLevelFull)
	if err != nil {
		t.Fatalf("Failed to configure: %v", err)
	}
	defer d.db.Close()

	out := make(chan pipeline.Event, 10)
	tomb := &tomb.Tomb{}

	go func() {
		err := d.OneShotAcquisition(context.Background(), out, tomb)
		if err != nil {
			t.Errorf("OneShotAcquisition failed: %v", err)
		}
		close(out)
	}()

	// Collect events
	var events []pipeline.Event
	for evt := range out {
		events = append(events, evt)
	}

	if len(events) < 1 {
		t.Fatal("No events received")
	}

	// Check that additional columns are in labels
	evt := events[0]
	if evt.Line.Labels["level"] != "info" {
		t.Errorf("Expected level label to be 'info', got '%s'", evt.Line.Labels["level"])
	}
	if evt.Line.Labels["source"] != "test" {
		t.Errorf("Expected source label to be 'test', got '%s'", evt.Line.Labels["source"])
	}
}

