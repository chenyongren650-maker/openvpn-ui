package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const createSchemaMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	checksum TEXT NOT NULL,
	applied_at DATETIME NOT NULL
)`

// Result reports changes made by one migration run.
type Result struct {
	AppliedVersions []int64
	BackupPath      string
}

type appliedMigration struct {
	Name     string
	Checksum string
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Up applies every pending migration to the configured SQLite database.
func Up(ctx context.Context, dbPath string) (Result, error) {
	return run(ctx, dbPath, registeredMigrations, time.Now)
}

func run(
	ctx context.Context,
	dbPath string,
	migrations []Migration,
	now func() time.Time,
) (Result, error) {
	var result Result

	if err := validateRegistry(migrations); err != nil {
		return result, err
	}

	absPath, existed, err := prepareDatabasePath(dbPath)
	if err != nil {
		return result, err
	}
	migrationLock, err := acquireMigrationFileLock(ctx, absPath)
	if err != nil {
		return result, fmt.Errorf("acquire SQLite migration lock: %w", err)
	}
	defer migrationLock.release()

	db, err := openSQLite(absPath)
	if err != nil {
		return result, fmt.Errorf("open SQLite database: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return result, fmt.Errorf("connect to SQLite database: %w", err)
	}

	applied, err := readAppliedMigrations(ctx, db)
	if err != nil {
		return result, err
	}
	pending, err := findPendingMigrations(migrations, applied)
	if err != nil {
		return result, err
	}
	if len(pending) == 0 {
		return result, nil
	}

	if existed {
		result.BackupPath, err = backupSQLite(ctx, db, absPath, pending[0].Version, now())
		if err != nil {
			return result, fmt.Errorf("back up SQLite database before migration: %w", err)
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin migration transaction: %w", err)
	}
	defer tx.Rollback()

	// Re-check after acquiring the SQLite immediate transaction lock. This keeps
	// concurrent application starts from applying the same migration twice.
	applied, err = readAppliedMigrations(ctx, tx)
	if err != nil {
		return result, err
	}
	pending, err = findPendingMigrations(migrations, applied)
	if err != nil {
		return result, err
	}
	if len(pending) == 0 {
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("commit no-op migration transaction: %w", err)
		}
		return result, nil
	}

	if _, err := tx.ExecContext(ctx, createSchemaMigrationsTable); err != nil {
		return result, fmt.Errorf("create schema_migrations table: %w", err)
	}

	appliedVersions := make([]int64, 0, len(pending))
	for _, migration := range pending {
		for statementIndex, statement := range migration.Up {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return result, fmt.Errorf(
					"apply migration %d (%s), statement %d: %w",
					migration.Version,
					migration.Name,
					statementIndex+1,
					err,
				)
			}
		}

		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO schema_migrations (version, name, checksum, applied_at)
			 VALUES (?, ?, ?, ?)`,
			migration.Version,
			migration.Name,
			migrationChecksum(migration),
			now().UTC().Format(time.RFC3339Nano),
		); err != nil {
			return result, fmt.Errorf(
				"record migration %d (%s): %w",
				migration.Version,
				migration.Name,
				err,
			)
		}
		appliedVersions = append(appliedVersions, migration.Version)
	}

	if err := tx.Commit(); err != nil {
		return result, fmt.Errorf("commit migration transaction: %w", err)
	}
	result.AppliedVersions = appliedVersions
	return result, nil
}

type migrationFileLock struct {
	file *os.File
}

func acquireMigrationFileLock(
	ctx context.Context,
	databasePath string,
) (*migrationFileLock, error) {
	lockPath := databasePath + ".migration.lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}

	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &migrationFileLock{file: file}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) &&
			!errors.Is(err, syscall.EAGAIN) {
			file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func (l *migrationFileLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}

func prepareDatabasePath(dbPath string) (absPath string, existed bool, err error) {
	if strings.TrimSpace(dbPath) == "" {
		return "", false, errors.New("SQLite database path is empty")
	}
	if dbPath == ":memory:" || strings.HasPrefix(dbPath, "file:") {
		return "", false, errors.New("SQLite database path must be a filesystem path")
	}

	absPath, err = filepath.Abs(dbPath)
	if err != nil {
		return "", false, fmt.Errorf("resolve SQLite database path: %w", err)
	}

	info, statErr := os.Stat(absPath)
	switch {
	case statErr == nil:
		if info.IsDir() {
			return "", false, fmt.Errorf("SQLite database path is a directory: %s", absPath)
		}
		existed = info.Size() > 0
	case errors.Is(statErr, os.ErrNotExist):
		existed = false
	default:
		return "", false, fmt.Errorf("inspect SQLite database path: %w", statErr)
	}

	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return "", false, fmt.Errorf("create SQLite database directory: %w", err)
	}
	return absPath, existed, nil
}

func openSQLite(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", sqliteDSN(dbPath))
	if err != nil {
		return nil, err
	}
	// A single connection keeps SQLite PRAGMA settings and transaction locking
	// consistent throughout one migration run.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

func sqliteDSN(dbPath string) string {
	dsn := &url.URL{Scheme: "file", Path: dbPath}
	query := dsn.Query()
	query.Set("_busy_timeout", "5000")
	query.Set("_foreign_keys", "on")
	query.Set("_txlock", "immediate")
	dsn.RawQuery = query.Encode()
	return dsn.String()
}

func validateRegistry(migrations []Migration) error {
	var previousVersion int64
	names := make(map[string]struct{}, len(migrations))
	for index, migration := range migrations {
		if migration.Version <= 0 {
			return fmt.Errorf("migration at index %d has invalid version %d", index, migration.Version)
		}
		if index > 0 && migration.Version <= previousVersion {
			return fmt.Errorf("migration versions must be strictly increasing")
		}
		if strings.TrimSpace(migration.Name) == "" {
			return fmt.Errorf("migration %d has an empty name", migration.Version)
		}
		if _, duplicate := names[migration.Name]; duplicate {
			return fmt.Errorf("migration name %q is duplicated", migration.Name)
		}
		if len(migration.Up) == 0 {
			return fmt.Errorf("migration %d (%s) has no Up statements", migration.Version, migration.Name)
		}
		if len(migration.Down) == 0 {
			return fmt.Errorf("migration %d (%s) has no Down statements", migration.Version, migration.Name)
		}

		names[migration.Name] = struct{}{}
		previousVersion = migration.Version
	}
	return nil
}

func readAppliedMigrations(ctx context.Context, db queryer) (map[int64]appliedMigration, error) {
	var tableCount int
	if err := db.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`,
	).Scan(&tableCount); err != nil {
		return nil, fmt.Errorf("check schema_migrations table: %w", err)
	}
	if tableCount == 0 {
		return map[int64]appliedMigration{}, nil
	}

	rows, err := db.QueryContext(
		ctx,
		`SELECT version, name, checksum FROM schema_migrations ORDER BY version`,
	)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]appliedMigration)
	for rows.Next() {
		var version int64
		var record appliedMigration
		if err := rows.Scan(&version, &record.Name, &record.Checksum); err != nil {
			return nil, fmt.Errorf("scan schema_migrations row: %w", err)
		}
		applied[version] = record
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations: %w", err)
	}
	return applied, nil
}

func findPendingMigrations(
	migrations []Migration,
	applied map[int64]appliedMigration,
) ([]Migration, error) {
	known := make(map[int64]Migration, len(migrations))
	for _, migration := range migrations {
		known[migration.Version] = migration
	}
	for version := range applied {
		if _, exists := known[version]; !exists {
			return nil, fmt.Errorf("database contains unknown migration version %d", version)
		}
	}

	pending := make([]Migration, 0, len(migrations))
	missingEarlierVersion := false
	for _, migration := range migrations {
		record, exists := applied[migration.Version]
		if !exists {
			missingEarlierVersion = true
			pending = append(pending, migration)
			continue
		}
		if missingEarlierVersion {
			return nil, fmt.Errorf(
				"database migration history is out of order at version %d",
				migration.Version,
			)
		}
		if record.Name != migration.Name {
			return nil, fmt.Errorf(
				"migration %d name mismatch: database has %q, code has %q",
				migration.Version,
				record.Name,
				migration.Name,
			)
		}
		expectedChecksum := migrationChecksum(migration)
		if record.Checksum != expectedChecksum {
			return nil, fmt.Errorf("migration %d checksum mismatch", migration.Version)
		}
	}
	return pending, nil
}

func migrationChecksum(migration Migration) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "%d\x00%s\x00", migration.Version, migration.Name)
	for _, statement := range migration.Up {
		hash.Write([]byte(statement))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func backupSQLite(
	ctx context.Context,
	sourceDB *sql.DB,
	sourcePath string,
	nextVersion int64,
	backupTime time.Time,
) (string, error) {
	backupDir := filepath.Join(filepath.Dir(sourcePath), "backups")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	if err := os.Chmod(backupDir, 0o700); err != nil {
		return "", fmt.Errorf("secure backup directory: %w", err)
	}

	timestamp := backupTime.UTC().Format("20060102T150405.000000000Z")
	backupName := fmt.Sprintf(
		"%s.%s.before-v%04d.bak",
		filepath.Base(sourcePath),
		timestamp,
		nextVersion,
	)
	backupPath := filepath.Join(backupDir, backupName)
	temporaryPath := backupPath + ".tmp"
	if _, err := os.Lstat(backupPath); err == nil {
		return "", fmt.Errorf("backup path already exists: %s", backupPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect backup path: %w", err)
	}

	temporaryFile, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("create temporary backup: %w", err)
	}
	defer func() {
		_ = os.Remove(temporaryPath)
		_ = os.Remove(temporaryPath + "-journal")
		_ = os.Remove(temporaryPath + "-wal")
		_ = os.Remove(temporaryPath + "-shm")
	}()
	if err := temporaryFile.Close(); err != nil {
		return "", fmt.Errorf("close temporary backup: %w", err)
	}

	if err := copySQLiteDatabase(ctx, sourceDB, temporaryPath); err != nil {
		return "", err
	}
	if err := verifySQLiteBackup(ctx, temporaryPath); err != nil {
		return "", err
	}
	if err := syncFile(temporaryPath); err != nil {
		return "", fmt.Errorf("sync temporary backup: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return "", fmt.Errorf("secure temporary backup: %w", err)
	}
	if err := os.Rename(temporaryPath, backupPath); err != nil {
		return "", fmt.Errorf("publish SQLite backup: %w", err)
	}
	if err := syncDirectory(backupDir); err != nil {
		return "", fmt.Errorf("sync backup directory: %w", err)
	}
	return backupPath, nil
}

func copySQLiteDatabase(ctx context.Context, sourceDB *sql.DB, destinationPath string) error {
	destinationDB, err := openSQLite(destinationPath)
	if err != nil {
		return fmt.Errorf("open backup destination: %w", err)
	}
	defer destinationDB.Close()

	sourceConn, err := sourceDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire source SQLite connection: %w", err)
	}
	defer sourceConn.Close()

	destinationConn, err := destinationDB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire destination SQLite connection: %w", err)
	}
	defer destinationConn.Close()

	err = destinationConn.Raw(func(destinationDriverConn any) error {
		destinationSQLiteConn, ok := destinationDriverConn.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("unexpected destination SQLite driver connection %T", destinationDriverConn)
		}

		return sourceConn.Raw(func(sourceDriverConn any) error {
			sourceSQLiteConn, ok := sourceDriverConn.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("unexpected source SQLite driver connection %T", sourceDriverConn)
			}

			backup, err := destinationSQLiteConn.Backup("main", sourceSQLiteConn, "main")
			if err != nil {
				return fmt.Errorf("initialize SQLite online backup: %w", err)
			}
			for {
				done, stepErr := backup.Step(128)
				if stepErr != nil {
					_ = backup.Finish()
					return fmt.Errorf("copy SQLite backup pages: %w", stepErr)
				}
				if done {
					break
				}
				select {
				case <-ctx.Done():
					_ = backup.Finish()
					return ctx.Err()
				case <-time.After(5 * time.Millisecond):
				}
			}
			if err := backup.Finish(); err != nil {
				return fmt.Errorf("finish SQLite online backup: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	return nil
}

func verifySQLiteBackup(ctx context.Context, backupPath string) error {
	db, err := openSQLite(backupPath)
	if err != nil {
		return fmt.Errorf("open SQLite backup for verification: %w", err)
	}
	defer db.Close()

	var integrityResult string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrityResult); err != nil {
		return fmt.Errorf("verify SQLite backup integrity: %w", err)
	}
	if integrityResult != "ok" {
		return fmt.Errorf("SQLite backup integrity check returned %q", integrityResult)
	}
	return nil
}

func syncFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
