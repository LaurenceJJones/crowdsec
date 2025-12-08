//go:build !no_datasource_database

package acquisition

import (
	databaseacquisition "github.com/crowdsecurity/crowdsec/pkg/acquisition/modules/database"
)

var (
	// verify interface compliance
	_ DataSource      = (*databaseacquisition.DatabaseSource)(nil)
	_ DSNConfigurer   = (*databaseacquisition.DatabaseSource)(nil)
	_ Fetcher         = (*databaseacquisition.DatabaseSource)(nil)
	_ Tailer          = (*databaseacquisition.DatabaseSource)(nil)
	_ MetricsProvider = (*databaseacquisition.DatabaseSource)(nil)
)

//nolint:gochecknoinits
func init() {
	registerDataSource("database", func() DataSource { return &databaseacquisition.DatabaseSource{} })
}
