// SQLite connection setup acquires the file lock before any store operation.
// The SQL pool repeats this step whenever it replaces its physical connection.
package session

import (
	"context"
	"database/sql/driver"

	"modernc.org/sqlite"
)

// ---------- Exclusive ownership ----------

type exclusiveConnector struct{ driver.Connector }

func (c exclusiveConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	executor := conn.(sqlite.ExecQuerierContext)
	// locking_mode alone delays the exclusive lock until a transaction needs it.
	for _, query := range []string{"BEGIN EXCLUSIVE", "COMMIT"} {
		if _, err := executor.ExecContext(ctx, query, nil); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}
