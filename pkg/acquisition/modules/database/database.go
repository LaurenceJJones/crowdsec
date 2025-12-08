package databaseacquisition

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	yaml "github.com/goccy/go-yaml"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	tomb "gopkg.in/tomb.v2"

	"github.com/crowdsecurity/crowdsec/pkg/acquisition/configuration"
	"github.com/crowdsecurity/crowdsec/pkg/metrics"
	"github.com/crowdsecurity/crowdsec/pkg/pipeline"

	// Database drivers - imported for side effects
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultPollInterval  = 10 * time.Second
	timestampPlaceholder = "{{.timestamp}}"
)

type TLSConfig struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	ClientCert         string `yaml:"client_cert"`
	ClientKey          string `yaml:"client_key"`
	CaCert             string `yaml:"ca_cert"`
}

type DatabaseConfiguration struct {
	DSN                               string        `yaml:"dsn"`                // Database connection string
	Driver                            string        `yaml:"driver"`             // Database driver (postgres, mysql, sqlite3, etc.)
	Query                             string        `yaml:"query"`              // SQL query to execute
	PollInterval                      time.Duration `yaml:"poll_interval"`      // How often to poll for new data (tail mode)
	LogColumn                         string        `yaml:"log_column"`         // Column containing the log message
	TimestampColumn                   string        `yaml:"timestamp_column"`   // Column containing timestamp for incremental reads
	MaxRows                           int           `yaml:"max_rows"`           // Maximum rows per query (default: 1000)
	AdditionalColumns                 []string      `yaml:"additional_columns"` // Additional columns to add as labels
	TLS                               *TLSConfig    `yaml:"tls"`                // TLS configuration
	configuration.DataSourceCommonCfg `yaml:",inline"`
}

type DatabaseSource struct {
	metricsLevel  metrics.AcquisitionMetricsLevel
	config        DatabaseConfiguration
	logger        *log.Entry
	db            *sql.DB
	lastTimestamp time.Time
}

func (d *DatabaseSource) GetUuid() string {
	return d.config.UniqueId
}

func (d *DatabaseSource) UnmarshalConfig(yamlConfig []byte) error {
	d.config = DatabaseConfiguration{}

	err := yaml.UnmarshalWithOptions(yamlConfig, &d.config, yaml.Strict())
	if err != nil {
		return fmt.Errorf("cannot parse database acquisition configuration: %s", yaml.FormatError(err, false, false))
	}

	if d.logger != nil {
		d.logger.Tracef("Database acquisition configuration: %+v", d.config)
	}

	if d.config.DSN == "" {
		return errors.New("dsn is mandatory for database source")
	}

	if d.config.Driver == "" {
		return errors.New("driver is mandatory for database source (postgres, mysql, sqlite3)")
	}

	if d.config.Query == "" {
		return errors.New("query is mandatory for database source")
	}

	if d.config.LogColumn == "" {
		return errors.New("log_column is mandatory for database source")
	}

	if d.config.Mode == "" {
		d.config.Mode = configuration.TAIL_MODE
	}

	if d.config.Mode != configuration.CAT_MODE && d.config.Mode != configuration.TAIL_MODE {
		return fmt.Errorf("unsupported mode %s for database source", d.config.Mode)
	}

	if d.config.PollInterval == 0 {
		d.config.PollInterval = defaultPollInterval
	}

	if d.config.MaxRows == 0 {
		d.config.MaxRows = 1000
	}

	// Validate that if timestamp_column is set, the query contains the placeholder
	if d.config.TimestampColumn != "" && !strings.Contains(d.config.Query, timestampPlaceholder) {
		return fmt.Errorf("query must contain %s when timestamp_column is set. Example: WHERE created_at > '%s'", timestampPlaceholder, timestampPlaceholder)
	}

	// Helpful warning: if in tail mode and no timestamp tracking, warn about duplicate reads
	if d.config.Mode == configuration.TAIL_MODE && d.config.TimestampColumn == "" {
		if d.logger != nil {
			d.logger.Warnf("Running in tail mode without timestamp_column - will re-read all rows on each poll. Consider setting timestamp_column for incremental reads")
		}
	}

	// Helpful hint: if timestamp_column is set but query looks like it might be missing ORDER BY
	if d.config.TimestampColumn != "" && !strings.Contains(strings.ToUpper(d.config.Query), "ORDER BY") {
		if d.logger != nil {
			d.logger.Warnf("Query has timestamp_column but no ORDER BY clause - consider adding ORDER BY %s for consistent results", d.config.TimestampColumn)
		}
	}

	return nil
}

func (d *DatabaseConfiguration) NewTLSConfig() (*tls.Config, error) {
	tlsConfig := tls.Config{
		InsecureSkipVerify: d.TLS.InsecureSkipVerify,
	}

	// Load client certificate if provided
	if d.TLS.ClientCert != "" && d.TLS.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(d.TLS.ClientCert, d.TLS.ClientKey)
		if err != nil {
			return &tlsConfig, fmt.Errorf("failed to load client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if d.TLS.CaCert != "" {
		caCert, err := os.ReadFile(d.TLS.CaCert)
		if err != nil {
			return &tlsConfig, fmt.Errorf("failed to read ca cert: %w", err)
		}

		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			return &tlsConfig, fmt.Errorf("unable to load system CA certificates: %w", err)
		}

		if caCertPool == nil {
			caCertPool = x509.NewCertPool()
		}

		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	return &tlsConfig, nil
}

func (d *DatabaseSource) configureTLS(dsn string) (string, error) {
	tlsConfig, err := d.config.NewTLSConfig()
	if err != nil {
		return dsn, fmt.Errorf("failed to create TLS config: %w", err)
	}

	switch d.config.Driver {
	case "mysql":
		// Register TLS config for MySQL
		tlsConfigName := fmt.Sprintf("crowdsec-db-%s", d.config.UniqueId)
		if err := mysql.RegisterTLSConfig(tlsConfigName, tlsConfig); err != nil {
			return dsn, fmt.Errorf("failed to register MySQL TLS config: %w", err)
		}

		// Add tls parameter to DSN
		if strings.Contains(dsn, "?") {
			dsn = fmt.Sprintf("%s&tls=%s", dsn, tlsConfigName)
		} else {
			dsn = fmt.Sprintf("%s?tls=%s", dsn, tlsConfigName)
		}
		d.logger.Debugf("Configured MySQL TLS with config name: %s", tlsConfigName)

	case "postgres":
		// PostgreSQL uses connection parameters
		// Build sslmode parameter
		sslMode := "require"
		if d.config.TLS.InsecureSkipVerify {
			sslMode = "disable"
		} else if d.config.TLS.CaCert != "" {
			sslMode = "verify-full"
		}

		// Add SSL parameters to DSN
		if strings.Contains(dsn, "sslmode=") {
			d.logger.Warnf("DSN already contains sslmode parameter. TLS configuration will override it with sslmode=%s. Consider removing sslmode from DSN.", sslMode)
			// Remove existing sslmode to avoid conflicts
			dsn = removeDSNParam(dsn, "sslmode")
		}
		dsn = fmt.Sprintf("%s sslmode=%s", dsn, sslMode)

		if d.config.TLS.CaCert != "" {
			dsn = fmt.Sprintf("%s sslrootcert=%s", dsn, d.config.TLS.CaCert)
		}

		if d.config.TLS.ClientCert != "" {
			dsn = fmt.Sprintf("%s sslcert=%s", dsn, d.config.TLS.ClientCert)
		}

		if d.config.TLS.ClientKey != "" {
			dsn = fmt.Sprintf("%s sslkey=%s", dsn, d.config.TLS.ClientKey)
		}

		d.logger.Debugf("Configured PostgreSQL TLS with sslmode: %s", sslMode)

	case "sqlite3":
		d.logger.Warnf("TLS configuration is not applicable for SQLite (local file database)")

	default:
		return dsn, fmt.Errorf("TLS configuration not supported for driver: %s", d.config.Driver)
	}

	return dsn, nil
}

// removeDSNParam removes a parameter from PostgreSQL DSN connection string
func removeDSNParam(dsn, param string) string {
	parts := strings.Split(dsn, " ")
	var filtered []string
	for _, part := range parts {
		if !strings.HasPrefix(part, param+"=") {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, " ")
}

func (d *DatabaseSource) Configure(_ context.Context, yamlConfig []byte, logger *log.Entry, metricsLevel metrics.AcquisitionMetricsLevel) error {
	d.logger = logger
	d.metricsLevel = metricsLevel

	err := d.UnmarshalConfig(yamlConfig)
	if err != nil {
		return err
	}

	d.logger.Tracef("Actual database acquisition configuration %+v", d.config)

	// Handle TLS configuration if provided
	dsn := d.config.DSN
	if d.config.TLS != nil {
		var tlsErr error
		dsn, tlsErr = d.configureTLS(dsn)
		if tlsErr != nil {
			return fmt.Errorf("failed to configure TLS: %w", tlsErr)
		}
	}

	// Open database connection
	d.db, err = sql.Open(d.config.Driver, dsn)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	d.logger.Infof("Successfully connected to %s database", d.config.Driver)

	// Set connection pool settings
	d.db.SetMaxOpenConns(5)
	d.db.SetMaxIdleConns(2)
	d.db.SetConnMaxLifetime(time.Hour)

	// Initialize last timestamp to now if in tail mode
	if d.config.Mode == configuration.TAIL_MODE && d.config.TimestampColumn != "" {
		d.lastTimestamp = time.Now()
	}

	return nil
}

func (d *DatabaseSource) ConfigureByDSN(_ context.Context, dsn string, labels map[string]string, logger *log.Entry, uuid string) error {
	if !strings.HasPrefix(dsn, "database://") {
		return fmt.Errorf("invalid DSN %s for database source, must start with database://", dsn)
	}

	d.logger = logger
	d.config = DatabaseConfiguration{}
	d.config.Labels = labels
	d.config.UniqueId = uuid
	d.config.Mode = configuration.CAT_MODE

	// Parse DSN: database://driver@host/dbname?query=SELECT...&log_column=message
	dsn = strings.TrimPrefix(dsn, "database://")

	u, err := url.Parse("dummy://" + dsn)
	if err != nil {
		return fmt.Errorf("failed to parse DSN: %w", err)
	}

	// Extract driver from userinfo
	if u.User != nil {
		d.config.Driver = u.User.Username()
	}

	if d.config.Driver == "" {
		return errors.New("driver must be specified in DSN (database://driver@...)")
	}

	// Parse query parameters
	params := u.Query()

	if q := params.Get("query"); q != "" {
		d.config.Query = q
	} else {
		return errors.New("query parameter is required")
	}

	if lc := params.Get("log_column"); lc != "" {
		d.config.LogColumn = lc
	} else {
		return errors.New("log_column parameter is required")
	}

	if tc := params.Get("timestamp_column"); tc != "" {
		d.config.TimestampColumn = tc
	}

	if mr := params.Get("max_rows"); mr != "" {
		maxRows, err := strconv.Atoi(mr)
		if err != nil {
			return fmt.Errorf("invalid max_rows: %w", err)
		}
		d.config.MaxRows = maxRows
	} else {
		d.config.MaxRows = 1000
	}

	if pi := params.Get("poll_interval"); pi != "" {
		pollInterval, err := time.ParseDuration(pi)
		if err != nil {
			return fmt.Errorf("invalid poll_interval: %w", err)
		}
		d.config.PollInterval = pollInterval
	} else {
		d.config.PollInterval = defaultPollInterval
	}

	// Reconstruct the actual database DSN (remove our custom params)
	params.Del("query")
	params.Del("log_column")
	params.Del("timestamp_column")
	params.Del("max_rows")
	params.Del("poll_interval")

	// Rebuild DSN for the database driver
	dbDSN := fmt.Sprintf("%s:%s@%s", u.User.Username(), "", u.Host)
	if u.Path != "" {
		dbDSN += u.Path
	}
	if len(params) > 0 {
		dbDSN += "?" + params.Encode()
	}

	d.config.DSN = dbDSN

	// Open database connection
	d.db, err = sql.Open(d.config.Driver, d.config.DSN)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %w", err)
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := d.db.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	d.logger.Infof("Successfully connected to %s database via DSN", d.config.Driver)

	return nil
}

func (d *DatabaseSource) GetMode() string {
	return d.config.Mode
}

func (*DatabaseSource) SupportedModes() []string {
	return []string{configuration.TAIL_MODE, configuration.CAT_MODE}
}

func (*DatabaseSource) GetName() string {
	return "database"
}

func (*DatabaseSource) CanRun() error {
	return nil
}

func (*DatabaseSource) GetMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.DatabaseDatasourceLinesRead}
}

func (*DatabaseSource) GetAggregMetrics() []prometheus.Collector {
	return []prometheus.Collector{metrics.DatabaseDatasourceLinesRead}
}

func (d *DatabaseSource) Dump() any {
	return d
}

// buildQuery replaces the timestamp placeholder with the actual timestamp value
func (d *DatabaseSource) buildQuery() string {
	query := d.config.Query

	if d.config.TimestampColumn != "" && strings.Contains(query, timestampPlaceholder) {
		// Format timestamp for SQL (ISO 8601)
		timestampStr := d.lastTimestamp.Format("2006-01-02 15:04:05.999999")
		query = strings.ReplaceAll(query, timestampPlaceholder, timestampStr)
	}

	return query
}

// executeQuery executes the SQL query and returns rows
func (d *DatabaseSource) executeQuery(ctx context.Context) (*sql.Rows, error) {
	query := d.buildQuery()
	d.logger.Tracef("Executing query: %s", query)

	rows, err := d.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	return rows, nil
}

// processRows reads rows from the database and sends them to the output channel
func (d *DatabaseSource) processRows(rows *sql.Rows, out chan pipeline.Event, t *tomb.Tomb) error {
	defer rows.Close()

	// Get column names
	columns, err := rows.Columns()
	if err != nil {
		return fmt.Errorf("failed to get columns: %w", err)
	}

	// Find log column index
	logColIndex := -1
	timestampColIndex := -1

	for i, col := range columns {
		if col == d.config.LogColumn {
			logColIndex = i
		}
		if d.config.TimestampColumn != "" && col == d.config.TimestampColumn {
			timestampColIndex = i
		}
	}

	if logColIndex == -1 {
		return fmt.Errorf("log column %s not found in query results", d.config.LogColumn)
	}

	// Process rows
	rowCount := 0
	var latestTimestamp time.Time

	for rows.Next() {
		select {
		case <-t.Dying():
			return nil
		default:
		}

		if d.config.MaxRows > 0 && rowCount >= d.config.MaxRows {
			d.logger.Debugf("Reached max_rows limit of %d", d.config.MaxRows)
			break
		}

		// Create slice to hold column values
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			d.logger.Errorf("Failed to scan row: %s", err)
			continue
		}

		// Extract log message
		var logMessage string
		if val := values[logColIndex]; val != nil {
			switch v := val.(type) {
			case []byte:
				logMessage = string(v)
			case string:
				logMessage = v
			default:
				logMessage = fmt.Sprintf("%v", v)
			}
		}

		if logMessage == "" {
			continue
		}

		// Extract timestamp if available
		var timestamp time.Time
		if timestampColIndex != -1 && values[timestampColIndex] != nil {
			switch v := values[timestampColIndex].(type) {
			case time.Time:
				timestamp = v
			case []byte:
				timestamp, _ = time.Parse("2006-01-02 15:04:05", string(v))
			case string:
				timestamp, _ = time.Parse("2006-01-02 15:04:05", v)
			default:
				timestamp = time.Now()
			}

			// Track latest timestamp
			if timestamp.After(latestTimestamp) {
				latestTimestamp = timestamp
			}
		} else {
			timestamp = time.Now()
		}

		// Create labels from additional columns
		labels := make(map[string]string)
		for k, v := range d.config.Labels {
			labels[k] = v
		}

		for _, colName := range d.config.AdditionalColumns {
			for i, col := range columns {
				if col == colName && values[i] != nil {
					labels[colName] = fmt.Sprintf("%v", values[i])
					break
				}
			}
		}

		// Create pipeline event
		l := pipeline.Line{
			Raw:     logMessage,
			Time:    timestamp,
			Src:     d.config.Driver,
			Labels:  labels,
			Process: true,
			Module:  d.GetName(),
		}

		d.logger.Debugf("Processing log: %s", logMessage)

		if d.metricsLevel != metrics.AcquisitionMetricsLevelNone {
			metrics.DatabaseDatasourceLinesRead.With(prometheus.Labels{
				"source":          d.config.Driver,
				"datasource_type": "database",
				"acquis_type":     l.Labels["type"],
			}).Inc()
		}

		evt := pipeline.MakeEvent(d.config.UseTimeMachine, pipeline.LOG, true)
		evt.Line = l
		out <- evt

		rowCount++
	}

	// Update last timestamp for next query
	if !latestTimestamp.IsZero() {
		d.lastTimestamp = latestTimestamp
		d.logger.Debugf("Updated last timestamp to %s", latestTimestamp)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating rows: %w", err)
	}

	d.logger.Debugf("Processed %d rows", rowCount)

	return nil
}

// OneShotAcquisition reads data once and returns
func (d *DatabaseSource) OneShotAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	d.logger.Info("Starting one-shot database acquisition")

	rows, err := d.executeQuery(ctx)
	if err != nil {
		return err
	}

	if err := d.processRows(rows, out, t); err != nil {
		return err
	}

	d.logger.Info("One-shot database acquisition completed")
	return nil
}

// StreamingAcquisition continuously polls the database for new data
func (d *DatabaseSource) StreamingAcquisition(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	d.logger.Info("Starting streaming database acquisition")

	ticker := time.NewTicker(d.config.PollInterval)
	defer ticker.Stop()

	// Do an initial query
	if err := d.queryAndProcess(ctx, out, t); err != nil {
		d.logger.Errorf("Error in initial query: %s", err)
	}

	for {
		select {
		case <-t.Dying():
			d.logger.Info("Database datasource stopping")
			if d.db != nil {
				d.db.Close()
			}
			return nil
		case <-ticker.C:
			if err := d.queryAndProcess(ctx, out, t); err != nil {
				d.logger.Errorf("Error querying database: %s", err)
			}
		}
	}
}

func (d *DatabaseSource) queryAndProcess(ctx context.Context, out chan pipeline.Event, t *tomb.Tomb) error {
	rows, err := d.executeQuery(ctx)
	if err != nil {
		return err
	}

	return d.processRows(rows, out, t)
}
