# Database Datasource for CrowdSec

The database datasource allows CrowdSec to read logs directly from SQL databases. This is useful when your application logs are stored in a database rather than files.

## Features

- **Multiple Database Support**: Works with any database that has a Go `database/sql` driver
  - PostgreSQL
  - MySQL/MariaDB
  - SQLite
  - And more...

- **Incremental Reading**: Use timestamp-based queries to only fetch new logs
- **Flexible Queries**: Write custom SQL queries to fetch exactly what you need
- **Column Mapping**: Map additional columns to labels for use in scenarios
- **Two Modes**:
  - **cat mode**: Read logs once and exit (useful for historical data)
  - **tail mode**: Continuously poll for new logs (useful for live monitoring)

## Configuration

### Required Fields

- `source`: Must be `database`
- `driver`: Database driver name (`postgres`, `mysql`, `sqlite3`)
- `dsn`: Database connection string (format depends on driver)
- `query`: SQL query to execute
- `log_column`: Name of the column containing the log message

### Optional Fields

- `timestamp_column`: Column containing timestamps for incremental reads
  - When set, your query must include `{{.timestamp}}` placeholder
- `poll_interval`: How often to poll (default: 10s, only for tail mode)
- `max_rows`: Maximum rows per query (default: 1000)
- `additional_columns`: List of columns to add as labels
- `mode`: `tail` or `cat` (default: `tail`)
- `labels`: Labels to apply to all events

## Examples

### PostgreSQL - Continuous Monitoring

```yaml
source: database
driver: postgres
dsn: "host=localhost port=5432 user=crowdsec password=pass dbname=logs sslmode=disable"
query: "SELECT message, created_at FROM logs WHERE created_at > '{{.timestamp}}' ORDER BY created_at"
log_column: message
timestamp_column: created_at
poll_interval: 10s
mode: tail
labels:
  type: postgresql-logs
```

### MySQL - One-Shot Read

```yaml
source: database
driver: mysql
dsn: "user:password@tcp(localhost:3306)/mydb?parseTime=true"
query: "SELECT log_text FROM application_logs ORDER BY id"
log_column: log_text
mode: cat
labels:
  type: mysql-logs
```

### SQLite - With Additional Labels

```yaml
source: database
driver: sqlite3
dsn: "/var/log/app.db"
query: "SELECT message, timestamp, severity FROM logs WHERE timestamp > '{{.timestamp}}'"
log_column: message
timestamp_column: timestamp
additional_columns:
  - severity
mode: tail
labels:
  type: sqlite-logs
```

## DSN (Data Source Name) Format

The DSN format depends on the database driver:

### PostgreSQL
```
host=localhost port=5432 user=myuser password=mypass dbname=mydb sslmode=disable
```

### MySQL
```
username:password@tcp(host:port)/dbname?parseTime=true
```

### SQLite
```
/path/to/database.db
```

## Query Templates

When using `timestamp_column`, you must include the `{{.timestamp}}` placeholder in your query:

```sql
SELECT log_message, created_at 
FROM logs 
WHERE created_at > '{{.timestamp}}' 
ORDER BY created_at ASC
```

The placeholder will be replaced with the last processed timestamp in the format `2006-01-02 15:04:05.999999`.

## Best Practices

1. **Always use ORDER BY**: Ensure logs are processed in chronological order
2. **Limit your queries**: Use `LIMIT` or `max_rows` to avoid overwhelming CrowdSec
3. **Index timestamp columns**: For better query performance
4. **Use appropriate poll_interval**: Balance between real-time detection and database load
5. **Test your queries**: Verify they return the expected columns before deploying

## Troubleshooting

### Connection Issues

If you can't connect to your database:
- Verify the DSN is correct
- Check firewall rules
- Ensure the database user has SELECT permissions
- Test connection with a database client first

### No Logs Appearing

If logs aren't being read:
- Verify `log_column` matches your table structure
- Check that your query returns results when run manually
- Enable debug logging: `log_level: debug`
- Check CrowdSec logs for errors

### Performance Issues

If database queries are slow:
- Add indexes on timestamp columns
- Reduce `max_rows`
- Increase `poll_interval`
- Optimize your SQL query

## Security Considerations

- **Use read-only database users**: The datasource only needs SELECT permission
- **Secure your DSN**: The connection string may contain passwords
- **Use SSL/TLS**: Enable secure connections when possible (`sslmode=require` for PostgreSQL)
- **Limit network access**: Restrict database access to the CrowdSec host

## Command Line Usage

You can also use the database datasource from the command line:

```bash
cscli explain --type database --dsn "database://postgres@localhost/mydb?query=SELECT+message+FROM+logs&log_column=message"
```

DSN format for command line:
```
database://driver@host/dbname?query=SELECT...&log_column=message&timestamp_column=ts
```

## Installation

The database datasource requires database drivers. Install them based on your needs:

```bash
go get github.com/lib/pq              # PostgreSQL
go get github.com/go-sql-driver/mysql # MySQL
go get github.com/mattn/go-sqlite3    # SQLite
```

These are already included in CrowdSec by default.

