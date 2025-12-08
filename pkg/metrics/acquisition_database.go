package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

const DatabaseDatasourceLinesReadMetricName = "cs_databasesource_hits_total"

var DatabaseDatasourceLinesRead = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: DatabaseDatasourceLinesReadMetricName,
		Help: "Total lines that were read from database.",
	},
	[]string{"source", "datasource_type", "acquis_type"},
)

//nolint:gochecknoinits
func init() {
	RegisterAcquisitionMetric(DatabaseDatasourceLinesReadMetricName)
}

