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
	{
		Version: 2,
		Name:    "certificate_history_compatibility",
		Up: []string{
			// Easy-RSA keeps certificate history by serial number. Renewed
			// certificates may reuse the same common name and static IP, so those
			// values cannot be unique identifiers in the application database.
			`CREATE TABLE certificates_v2 (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				vpn_user_id INTEGER,
				common_name TEXT NOT NULL,
				serial_number TEXT NOT NULL COLLATE NOCASE UNIQUE,
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
			`INSERT INTO certificates_v2 (
				id, vpn_user_id, common_name, serial_number, fingerprint, status,
				permission_type, static_ip, validity_mode, business_expires_at,
				technical_expires_at, device_note, created_at, revoked_at, archived_at
			)
			SELECT
				id, vpn_user_id, common_name, serial_number, fingerprint, status,
				permission_type, static_ip, validity_mode, business_expires_at,
				technical_expires_at, device_note, created_at, revoked_at, archived_at
			FROM certificates`,
			// Rebuild the child table in the same transaction so its foreign key
			// follows the replacement certificates table without losing metadata.
			`CREATE TABLE totp_identities_v2 (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				certificate_id INTEGER NOT NULL UNIQUE,
				tfa_name TEXT NOT NULL UNIQUE,
				issuer TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				reset_at DATETIME,
				last_verified_at DATETIME,
				FOREIGN KEY (certificate_id) REFERENCES certificates_v2(id)
					ON UPDATE CASCADE ON DELETE RESTRICT
			)`,
			`INSERT INTO totp_identities_v2 (
				id, certificate_id, tfa_name, issuer, status,
				created_at, reset_at, last_verified_at
			)
			SELECT
				id, certificate_id, tfa_name, issuer, status,
				created_at, reset_at, last_verified_at
			FROM totp_identities`,
			`DROP TABLE totp_identities`,
			`DROP TABLE certificates`,
			`ALTER TABLE certificates_v2 RENAME TO certificates`,
			`ALTER TABLE totp_identities_v2 RENAME TO totp_identities`,
			`CREATE UNIQUE INDEX idx_certificates_fingerprint
				ON certificates(fingerprint)
				WHERE fingerprint IS NOT NULL AND fingerprint <> ''`,
			`CREATE INDEX idx_certificates_common_name ON certificates(common_name)`,
			`CREATE INDEX idx_certificates_static_ip
				ON certificates(static_ip)
				WHERE static_ip IS NOT NULL AND static_ip <> ''`,
			`CREATE INDEX idx_certificates_vpn_user_id ON certificates(vpn_user_id)`,
			`CREATE INDEX idx_certificates_status ON certificates(status)`,
			`CREATE INDEX idx_certificates_archived_at ON certificates(archived_at)`,
			`CREATE INDEX idx_totp_identities_status ON totp_identities(status)`,
		},
		Down: []string{
			// Operational rollback restores the verified pre-v2 SQLite backup.
			// These statements document the original schema and intentionally fail
			// rather than discard data if duplicate CN or static IP history exists.
			`CREATE TABLE certificates_v1 (
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
			`INSERT INTO certificates_v1 (
				id, vpn_user_id, common_name, serial_number, fingerprint, status,
				permission_type, static_ip, validity_mode, business_expires_at,
				technical_expires_at, device_note, created_at, revoked_at, archived_at
			)
			SELECT
				id, vpn_user_id, common_name, serial_number, fingerprint, status,
				permission_type, static_ip, validity_mode, business_expires_at,
				technical_expires_at, device_note, created_at, revoked_at, archived_at
			FROM certificates`,
			`CREATE TABLE totp_identities_v1 (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				certificate_id INTEGER NOT NULL UNIQUE,
				tfa_name TEXT NOT NULL UNIQUE,
				issuer TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'active',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				reset_at DATETIME,
				last_verified_at DATETIME,
				FOREIGN KEY (certificate_id) REFERENCES certificates_v1(id)
					ON UPDATE CASCADE ON DELETE RESTRICT
			)`,
			`INSERT INTO totp_identities_v1 (
				id, certificate_id, tfa_name, issuer, status,
				created_at, reset_at, last_verified_at
			)
			SELECT
				id, certificate_id, tfa_name, issuer, status,
				created_at, reset_at, last_verified_at
			FROM totp_identities`,
			`DROP TABLE totp_identities`,
			`DROP TABLE certificates`,
			`ALTER TABLE certificates_v1 RENAME TO certificates`,
			`ALTER TABLE totp_identities_v1 RENAME TO totp_identities`,
			`CREATE UNIQUE INDEX idx_certificates_fingerprint
				ON certificates(fingerprint)
				WHERE fingerprint IS NOT NULL AND fingerprint <> ''`,
			`CREATE UNIQUE INDEX idx_certificates_static_ip
				ON certificates(static_ip)
				WHERE static_ip IS NOT NULL AND static_ip <> ''`,
			`CREATE INDEX idx_certificates_vpn_user_id ON certificates(vpn_user_id)`,
			`CREATE INDEX idx_certificates_status ON certificates(status)`,
			`CREATE INDEX idx_certificates_archived_at ON certificates(archived_at)`,
			`CREATE INDEX idx_totp_identities_status ON totp_identities(status)`,
		},
	},
	{
		Version: 3,
		Name:    "certificate_ip_allocations",
		Up: []string{
			// Keep one lifecycle allocation row per certificate. The partial
			// unique index prevents an address from being allocated or held for
			// release by two certificates while still allowing released history.
			`CREATE TABLE ip_allocations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL,
				pool_name TEXT NOT NULL DEFAULT 'restricted',
				certificate_id INTEGER NOT NULL UNIQUE,
				status TEXT NOT NULL DEFAULT 'allocated'
					CHECK (status IN ('allocated', 'pending_release', 'released')),
				allocated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				pending_release_at DATETIME,
				released_at DATETIME,
				notes TEXT NOT NULL DEFAULT '',
				FOREIGN KEY (certificate_id) REFERENCES certificates(id)
					ON UPDATE CASCADE ON DELETE RESTRICT
			)`,
			`CREATE UNIQUE INDEX idx_ip_allocations_active_ip
				ON ip_allocations(ip_address)
				WHERE status IN ('allocated', 'pending_release')`,
			`CREATE INDEX idx_ip_allocations_status ON ip_allocations(status)`,
			`CREATE INDEX idx_ip_allocations_certificate_id
				ON ip_allocations(certificate_id)`,
		},
		Down: []string{
			// Operational rollback should normally restore the verified
			// pre-v3 backup created by the migration runner. This statement is
			// retained for isolated development rollback verification.
			`DROP TABLE IF EXISTS ip_allocations`,
		},
	},
	{
		Version: 4,
		Name:    "vpn_users",
		Up: []string{
			`CREATE TABLE vpn_users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				display_name TEXT NOT NULL,
				username TEXT NOT NULL COLLATE NOCASE,
				email TEXT COLLATE NOCASE,
				department TEXT NOT NULL DEFAULT '',
				status TEXT NOT NULL DEFAULT 'active'
					CHECK (status IN ('active', 'disabled', 'archived')),
				notes TEXT NOT NULL DEFAULT '',
				created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				archived_at DATETIME
			)`,
			`CREATE UNIQUE INDEX idx_vpn_users_username
				ON vpn_users(username COLLATE NOCASE)`,
			`CREATE UNIQUE INDEX idx_vpn_users_email
				ON vpn_users(email COLLATE NOCASE)
				WHERE email IS NOT NULL AND trim(email) <> ''`,
			`CREATE INDEX idx_vpn_users_status ON vpn_users(status)`,
			`CREATE TRIGGER certificates_vpn_user_insert_guard
				BEFORE INSERT ON certificates
				WHEN NEW.vpn_user_id IS NOT NULL
					AND NOT EXISTS (
						SELECT 1 FROM vpn_users WHERE id = NEW.vpn_user_id
					)
				BEGIN
					SELECT RAISE(ABORT, 'certificates.vpn_user_id does not exist');
				END`,
			`CREATE TRIGGER certificates_vpn_user_update_guard
				BEFORE UPDATE OF vpn_user_id ON certificates
				WHEN NEW.vpn_user_id IS NOT NULL
					AND NOT EXISTS (
						SELECT 1 FROM vpn_users WHERE id = NEW.vpn_user_id
					)
				BEGIN
					SELECT RAISE(ABORT, 'certificates.vpn_user_id does not exist');
				END`,
			`CREATE TRIGGER vpn_users_delete_guard
				BEFORE DELETE ON vpn_users
				WHEN EXISTS (
					SELECT 1 FROM certificates WHERE vpn_user_id = OLD.id
				)
				BEGIN
					SELECT RAISE(ABORT, 'vpn_user is referenced by certificates');
				END`,
		},
		Down: []string{
			`DROP TRIGGER IF EXISTS vpn_users_delete_guard`,
			`DROP TRIGGER IF EXISTS certificates_vpn_user_update_guard`,
			`DROP TRIGGER IF EXISTS certificates_vpn_user_insert_guard`,
			`DROP TABLE IF EXISTS vpn_users`,
		},
	},
	{
		Version: 5,
		Name:    "ip_allocation_reservations",
		Up: []string{
			`CREATE TABLE ip_allocation_reservations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				ip_address TEXT NOT NULL,
				certificate_name TEXT NOT NULL COLLATE NOCASE,
				request_id TEXT NOT NULL,
				status TEXT NOT NULL DEFAULT 'reserved'
					CHECK (status IN ('reserved', 'completed', 'released')),
				reserved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				completed_at DATETIME,
				released_at DATETIME,
				error_summary TEXT NOT NULL DEFAULT ''
			)`,
			`CREATE UNIQUE INDEX idx_ip_reservations_active_ip
				ON ip_allocation_reservations(ip_address)
				WHERE status = 'reserved'`,
			`CREATE UNIQUE INDEX idx_ip_reservations_active_certificate
				ON ip_allocation_reservations(certificate_name COLLATE NOCASE)
				WHERE status = 'reserved'`,
			`CREATE INDEX idx_ip_reservations_certificate
				ON ip_allocation_reservations(certificate_name COLLATE NOCASE)`,
			`CREATE INDEX idx_ip_reservations_status
				ON ip_allocation_reservations(status)`,
		},
		Down: []string{
			`DROP TABLE IF EXISTS ip_allocation_reservations`,
		},
	},
}
