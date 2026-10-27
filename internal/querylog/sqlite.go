package querylog

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

const (
	batchSize       = 500
	batchInterval   = 60 * time.Second
	cleanupInterval = 24 * time.Hour
)

// SQLiteStore persistiert QueryLogEntries in einer SQLite-Datenbank.
// SD-Karten-freundlich: WAL-Mode + Batch-Commits (kein Schreiben pro Query).
type SQLiteStore struct {
	db          *sql.DB
	persistDays int
	batchCh     chan QueryLogEntry
}

// NewSQLiteStore öffnet (oder erstellt) eine SQLite-DB am angegebenen Pfad.
// dataDir wird als Fallback genutzt wenn path leer ist.
func NewSQLiteStore(path, dataDir string, persistDays int) (*SQLiteStore, error) {
	if path == "" {
		path = filepath.Join(dataDir, "query.log.db")
	}
	if persistDays <= 0 {
		persistDays = 7
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Verbindungspool auf 1 beschränken — SQLite ist single-writer
	db.SetMaxOpenConns(1)

	if err := applyPragmas(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply pragmas: %w", err)
	}

	if err := createSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &SQLiteStore{
		db:          db,
		persistDays: persistDays,
		batchCh:     make(chan QueryLogEntry, batchSize*2),
	}, nil
}

// Run startet den Batch-Write-Loop und den täglichen Cleanup-Job.
// Blockiert bis ctx abgebrochen wird. Als Goroutine starten.
func (s *SQLiteStore) Run(ctx context.Context) {
	batchTicker := time.NewTicker(batchInterval)
	cleanupTicker := time.NewTicker(cleanupInterval)
	defer batchTicker.Stop()
	defer cleanupTicker.Stop()

	buf := make([]QueryLogEntry, 0, batchSize)

	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := s.writeBatch(buf); err != nil {
			log.Warn().Err(err).Int("count", len(buf)).Msg("query log: sqlite batch write failed")
		} else {
			log.Debug().Int("count", len(buf)).Msg("query log: sqlite batch committed")
		}
		buf = buf[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Verbleibende Einträge im Channel noch schreiben, dann flushen
			for {
				select {
				case e := <-s.batchCh:
					buf = append(buf, e)
				default:
					flush()
					log.Info().Msg("query log: sqlite store flushed")
					return
				}
			}

		case e := <-s.batchCh:
			buf = append(buf, e)
			if len(buf) >= batchSize {
				flush()
			}

		case <-batchTicker.C:
			flush()

		case <-cleanupTicker.C:
			s.runCleanup()
		}
	}
}

// Close schließt die SQLite-Datenbankverbindung.
// Muss nach Run() aufgerufen werden.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Add schreibt einen Eintrag non-blocking in den Batch-Channel.
// Wenn der Channel voll ist, wird der Eintrag verworfen (SD-Karte nie blockieren).
func (s *SQLiteStore) Add(e QueryLogEntry) {
	select {
	case s.batchCh <- e:
	default:
		// Buffer voll → drop
	}
}

// Query gibt gefilterte, paginierte Einträge aus SQLite zurück.
// Genutzt wenn In-Memory-Ringbuffer nicht ausreicht (ältere Einträge).
func (s *SQLiteStore) Query(ctx context.Context, f QueryLogFilter) (QueryLogPage, error) {
	where, args := buildWhereClause(f)

	// Gesamtanzahl
	var total int
	countSQL := "SELECT COUNT(*) FROM query_log" + where
	if err := s.db.QueryRowContext(ctx, countSQL, args...).Scan(&total); err != nil {
		return QueryLogPage{}, fmt.Errorf("count query: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := fmt.Sprintf(
		"SELECT ts, node, client, domain, qtype, result, latency_us, upstream, blocked, cached, rcode "+
			"FROM query_log%s ORDER BY ts DESC LIMIT ? OFFSET ?",
		where,
	)
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, querySQL, args...)
	if err != nil {
		return QueryLogPage{}, fmt.Errorf("select query: %w", err)
	}
	defer rows.Close()

	entries := make([]QueryLogEntry, 0, limit)
	for rows.Next() {
		var e QueryLogEntry
		var ts int64
		if err := rows.Scan(
			&ts, &e.NodeID, &e.ClientIP, &e.Domain, &e.QType,
			&e.Result, &e.Latency, &e.Upstream, &e.Blocked, &e.Cached, &e.RCODE,
		); err != nil {
			return QueryLogPage{}, fmt.Errorf("scan row: %w", err)
		}
		e.Timestamp = time.UnixMicro(ts)
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return QueryLogPage{}, fmt.Errorf("rows error: %w", err)
	}

	return QueryLogPage{
		Entries: entries,
		Total:   total,
		HasMore: offset+limit < total,
	}, nil
}

// writeBatch schreibt alle Einträge in einer einzigen Transaktion.
func (s *SQLiteStore) writeBatch(entries []QueryLogEntry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.Prepare(
		"INSERT INTO query_log (ts, node, client, domain, qtype, result, latency_us, upstream, blocked, cached, rcode) " +
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
	)
	if err != nil {
		return fmt.Errorf("prepare stmt: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		_, err := stmt.Exec(
			e.Timestamp.UnixMicro(), e.NodeID, e.ClientIP, e.Domain, e.QType,
			e.Result, e.Latency, e.Upstream, e.Blocked, e.Cached, e.RCODE,
		)
		if err != nil {
			return fmt.Errorf("insert entry: %w", err)
		}
	}

	return tx.Commit()
}

// runCleanup löscht Einträge die älter als persistDays sind.
func (s *SQLiteStore) runCleanup() {
	cutoff := time.Now().AddDate(0, 0, -s.persistDays).UnixMicro()
	res, err := s.db.Exec("DELETE FROM query_log WHERE ts < ?", cutoff)
	if err != nil {
		log.Warn().Err(err).Msg("query log: sqlite cleanup failed")
		return
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		log.Info().Int64("deleted", n).Int("retain_days", s.persistDays).Msg("query log: sqlite cleanup done")
		// WAL-Checkpoint nach großem Cleanup
		_, _ = s.db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
	}
}

// applyPragmas setzt SD-Karten-freundliche SQLite-Einstellungen.
func applyPragmas(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",   // Write-Ahead Logging: weniger Write-Amplification
		"PRAGMA synchronous=NORMAL", // Schneller als FULL, sicher bei WAL
		"PRAGMA cache_size=-2000",   // 2 MB Page-Cache
		"PRAGMA temp_store=MEMORY",  // Temp-Tabellen im RAM
		"PRAGMA mmap_size=67108864", // 64 MB Memory-Map
		"PRAGMA foreign_keys=OFF",   // Keine FK-Constraints nötig
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// createSchema erstellt die Tabelle falls sie noch nicht existiert.
func createSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS query_log (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			ts         INTEGER NOT NULL,
			node       TEXT    NOT NULL DEFAULT '',
			client     TEXT    NOT NULL DEFAULT '',
			domain     TEXT    NOT NULL DEFAULT '',
			qtype      TEXT    NOT NULL DEFAULT '',
			result     TEXT    NOT NULL DEFAULT '',
			latency_us INTEGER NOT NULL DEFAULT 0,
			upstream   TEXT    NOT NULL DEFAULT '',
			blocked    INTEGER NOT NULL DEFAULT 0,
			cached     INTEGER NOT NULL DEFAULT 0,
			rcode      INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_query_log_ts     ON query_log(ts DESC);
		CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
		CREATE INDEX IF NOT EXISTS idx_query_log_client ON query_log(client);
		CREATE INDEX IF NOT EXISTS idx_query_log_result ON query_log(result);
	`)
	if err != nil {
		return fmt.Errorf("create table: %w", err)
	}
	return nil
}

// buildWhereClause baut die WHERE-Klausel aus einem QueryLogFilter.
func buildWhereClause(f QueryLogFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if f.Client != "" {
		conditions = append(conditions, "client LIKE ?")
		args = append(args, f.Client+"%")
	}
	if f.Domain != "" {
		conditions = append(conditions, "domain LIKE ?")
		args = append(args, "%"+f.Domain+"%")
	}
	if f.Result != "" {
		conditions = append(conditions, "result = ?")
		args = append(args, f.Result)
	}
	if f.QType != "" {
		conditions = append(conditions, "qtype = ?")
		args = append(args, f.QType)
	}
	if f.Node != "" {
		conditions = append(conditions, "node = ?")
		args = append(args, f.Node)
	}
	if !f.Since.IsZero() {
		conditions = append(conditions, "ts >= ?")
		args = append(args, f.Since.UnixMicro())
	}
	if !f.Until.IsZero() {
		conditions = append(conditions, "ts <= ?")
		args = append(args, f.Until.UnixMicro())
	}

	if len(conditions) == 0 {
		return "", args
	}

	where := " WHERE " + conditions[0]
	for _, c := range conditions[1:] {
		where += " AND " + c
	}
	return where, args
}
