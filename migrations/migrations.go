package migrations

// Migration describes one ordered, transactional database schema change.
type Migration struct {
	Version int64
	Name    string
	Up      []string
	Down    []string
}

var registeredMigrations = []Migration{
	{
		Version: 1,
		Name:    "p0_foundation_schema",
		Up: []string{
			// vpn_user_id intentionally remains nullable and has no foreign key
			// until the vpn_users table is introduced by a later migration.
			`CREATE TABLE certificates (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				vpn_user_id INTEGER,
				common_name TEXT NOT NULL UNIQUE,
				serial_number TEXT NOT NULL UNIQUE,
				fingerprint TEXT,
				status TEXT NOT NULL DEFAULT 'valid',
				permission_type TEXT NOT NULL DEFAULT 'normal',
				static_ip TEXT,
				validity_mode TEXT NOT NULL DEFAULT 'permanent',
				business_expires_at DATETIME,
				technical_expires_at DATETIME,
				device_note TEXT NOT NULL DEFAULT '',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				revoked_at DATETIME,
				archived_at DATETIME
			)`,
			`CREATE UNIQUE INDEX idx_certificates_fingerprint
				ON certificates(fingerprint)
				WHERE fingerprint IS NOT NULL AND fingerprint <> ''`,
			`CREATE UNIQUE INDEX idx_certificates_static_ip
				ON certificates(static_ip)
				WHERE static_ip IS NOT NULL AND static_ip <> ''`,
			`CREATE INDEX idx_certificates_vpn_user_id ON certificates(vpn_user_id)`,
			`CREATE INDEX idx_certificates_status ON certificates(status)`,
			`CREATE INDEX idx_certificates_archived_at ON certificates(archived_at)`,
			// TOTP secrets remain only in oath.secrets. This table stores identity
			// metadata and its stable certificate relationship, never secret data.
			`CREATE TABLE totp_identities (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				certificate_id INTEGER NOT NULL UNIQUE,
				tfa_name TEXT NOT NULL UNIQUE,
				issuer TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				reset_at DATETIME,
				last_verified_at DATETIME,
				FOREIGN KEY (certificate_id) REFERENCES certificates(id)
					ON UPDATE CASCADE ON DELETE RESTRICT
			)`,
			`CREATE INDEX idx_totp_identities_status ON totp_identities(status)`,
			`CREATE TABLE audit_logs (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				actor_user_id INTEGER,
				source_ip TEXT NOT NULL DEFAULT '',
				action TEXT NOT NULL,
				target_type TEXT NOT NULL,
				target_id TEXT NOT NULL DEFAULT '',
				summary TEXT NOT NULL DEFAULT '',
				result TEXT NOT NULL,
				error_summary TEXT NOT NULL DEFAULT '',
				request_id TEXT NOT NULL,
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			)`,
			`CREATE INDEX idx_audit_logs_actor_user_id ON audit_logs(actor_user_id)`,
			`CREATE INDEX idx_audit_logs_action ON audit_logs(action)`,
			`CREATE INDEX idx_audit_logs_target ON audit_logs(target_type, target_id)`,
			`CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id)`,
			`CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at)`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS audit_logs`,
			`DROP TABLE IF EXISTS totp_identities`,
			`DROP TABLE IF EXISTS certificates`,
		},
	},
}
