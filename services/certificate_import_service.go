package services

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

const maxCertificateIndexLineSize = 1024 * 1024

var certificateSerialPattern = regexp.MustCompile(`^[0-9A-Fa-f]+$`)

// CertificateImportResult reports non-sensitive certificate import counts.
type CertificateImportResult struct {
	Inserted      int
	Updated       int
	Unchanged     int
	SourceMissing bool
}

type certificateMetadata struct {
	CommonName         string
	SerialNumber       string
	Status             string
	StaticIP           *string
	TFAName            *string
	TechnicalExpiresAt time.Time
	RevokedAt          *time.Time
}

// ImportCertificateMetadataFile reads an Easy-RSA index in read-only mode and
// imports its certificate metadata in one database transaction. A missing
// index is a safe no-op so a new test PKI can initialize independently.
func ImportCertificateMetadataFile(
	ctx context.Context,
	db *sql.DB,
	indexPath string,
) (CertificateImportResult, error) {
	return importCertificateMetadataFile(ctx, db, indexPath, time.Now().UTC())
}

func importCertificateMetadataFile(
	ctx context.Context,
	db *sql.DB,
	indexPath string,
	now time.Time,
) (CertificateImportResult, error) {
	var result CertificateImportResult
	if db == nil {
		return result, errors.New("certificate metadata database is nil")
	}

	indexFile, err := os.Open(indexPath)
	if errors.Is(err, os.ErrNotExist) {
		result.SourceMissing = true
		return result, nil
	}
	if err != nil {
		return result, fmt.Errorf("open certificate index for reading: %w", err)
	}
	defer indexFile.Close()

	records, err := parseCertificateIndex(indexFile, now)
	if err != nil {
		return result, err
	}
	return importCertificateMetadata(ctx, db, records, now)
}

func parseCertificateIndex(reader io.Reader, now time.Time) ([]certificateMetadata, error) {
	if reader == nil {
		return nil, errors.New("certificate index reader is nil")
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxCertificateIndexLineSize)
	records := make([]certificateMetadata, 0)
	seenSerials := make(map[string]int)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}

		record, err := parseCertificateIndexLine(line, lineNumber, now.UTC())
		if err != nil {
			return nil, err
		}
		if previousLine, exists := seenSerials[record.SerialNumber]; exists {
			return nil, fmt.Errorf(
				"certificate index line %d duplicates serial from line %d",
				lineNumber,
				previousLine,
			)
		}
		seenSerials[record.SerialNumber] = lineNumber
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read certificate index: %w", err)
	}
	return records, nil
}

func parseCertificateIndexLine(
	line string,
	lineNumber int,
	now time.Time,
) (certificateMetadata, error) {
	var record certificateMetadata
	fields := strings.Split(line, "\t")
	if len(fields) != 6 {
		return record, fmt.Errorf(
			"certificate index line %d has %d fields, want 6",
			lineNumber,
			len(fields),
		)
	}

	entryType := strings.TrimSpace(fields[0])
	if entryType != "V" && entryType != "R" && entryType != "E" {
		return record, fmt.Errorf(
			"certificate index line %d has unsupported status",
			lineNumber,
		)
	}

	expiresAt, err := parseCertificateIndexTime(fields[1], lineNumber, "expiration")
	if err != nil {
		return record, err
	}

	serialNumber := strings.ToUpper(strings.TrimSpace(fields[3]))
	if serialNumber == "" || !certificateSerialPattern.MatchString(serialNumber) {
		return record, fmt.Errorf(
			"certificate index line %d has an invalid serial number",
			lineNumber,
		)
	}

	commonName, localIP, tfaName, err := parseCertificateIndexSubject(
		fields[5],
		lineNumber,
	)
	if err != nil {
		return record, err
	}
	staticIP, err := normalizeCertificateStaticIP(localIP, lineNumber)
	if err != nil {
		return record, err
	}
	normalizedTFAName, err := normalizeCertificateTFAName(tfaName, lineNumber)
	if err != nil {
		return record, err
	}

	status := "valid"
	var revokedAt *time.Time
	switch entryType {
	case "R":
		revocationTime, parseErr := parseCertificateIndexTime(
			fields[2],
			lineNumber,
			"revocation",
		)
		if parseErr != nil {
			return record, parseErr
		}
		status = "revoked"
		revocationTime = revocationTime.UTC()
		revokedAt = &revocationTime
	case "E":
		status = "expired"
	case "V":
		if !expiresAt.After(now) {
			status = "expired"
		}
	}

	record = certificateMetadata{
		CommonName:         commonName,
		SerialNumber:       serialNumber,
		Status:             status,
		StaticIP:           staticIP,
		TFAName:            normalizedTFAName,
		TechnicalExpiresAt: expiresAt.UTC(),
		RevokedAt:          revokedAt,
	}
	return record, nil
}

func parseCertificateIndexTime(value string, lineNumber int, fieldName string) (time.Time, error) {
	timestamp := strings.TrimSpace(value)
	if commaIndex := strings.IndexByte(timestamp, ','); commaIndex >= 0 {
		timestamp = timestamp[:commaIndex]
	}
	if timestamp == "" {
		return time.Time{}, fmt.Errorf(
			"certificate index line %d has an empty %s time",
			lineNumber,
			fieldName,
		)
	}

	for _, layout := range []string{"060102150405Z", "20060102150405Z"} {
		parsed, err := time.Parse(layout, timestamp)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf(
		"certificate index line %d has an invalid %s time",
		lineNumber,
		fieldName,
	)
}

func parseCertificateIndexSubject(
	subject string,
	lineNumber int,
) (string, string, string, error) {
	parts, err := splitCertificateSubject(subject)
	if err != nil {
		return "", "", "", fmt.Errorf(
			"certificate index line %d has an invalid subject",
			lineNumber,
		)
	}

	var commonName string
	var localIP string
	var tfaName string
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found || strings.TrimSpace(key) == "" {
			return "", "", "", fmt.Errorf(
				"certificate index line %d has an invalid subject attribute",
				lineNumber,
			)
		}
		value = strings.TrimSpace(value)
		switch key {
		case "CN":
			if commonName != "" && commonName != value {
				return "", "", "", fmt.Errorf(
					"certificate index line %d has conflicting common names",
					lineNumber,
				)
			}
			commonName = value
		case "LocalIP":
			if localIP != "" && localIP != value {
				return "", "", "", fmt.Errorf(
					"certificate index line %d has conflicting static IP metadata",
					lineNumber,
				)
			}
			localIP = value
		case "2FAName":
			if tfaName != "" && tfaName != value {
				return "", "", "", fmt.Errorf(
					"certificate index line %d has conflicting 2FA identity metadata",
					lineNumber,
				)
			}
			tfaName = value
		}
	}
	if commonName == "" {
		return "", "", "", fmt.Errorf(
			"certificate index line %d has no common name",
			lineNumber,
		)
	}
	return commonName, localIP, tfaName, nil
}

func splitCertificateSubject(subject string) ([]string, error) {
	parts := make([]string, 0)
	var current strings.Builder
	escaped := false
	for _, character := range subject {
		switch {
		case escaped:
			current.WriteRune(character)
			escaped = false
		case character == '\\':
			escaped = true
		case character == '/':
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(character)
		}
	}
	if escaped {
		return nil, errors.New("subject ends with an incomplete escape")
	}
	parts = append(parts, current.String())
	return parts, nil
}

func normalizeCertificateStaticIP(value string, lineNumber int) (*string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "dynamic.pool") || strings.EqualFold(value, "none") {
		return nil, nil
	}

	parsed := net.ParseIP(value)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf(
			"certificate index line %d has invalid static IP metadata",
			lineNumber,
		)
	}
	normalized := parsed.To4().String()
	return &normalized, nil
}

func normalizeCertificateTFAName(value string, lineNumber int) (*string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "none") {
		return nil, nil
	}
	if !ValidateCertificateCommonName(value) {
		return nil, fmt.Errorf(
			"certificate index line %d has invalid 2FA identity metadata",
			lineNumber,
		)
	}
	return &value, nil
}

func importCertificateMetadata(
	ctx context.Context,
	db *sql.DB,
	records []certificateMetadata,
	importedAt time.Time,
) (CertificateImportResult, error) {
	var result CertificateImportResult
	if db == nil {
		return result, errors.New("certificate metadata database is nil")
	}

	latestSerialByCommonName := make(map[string]string)
	latestTFANameByCommonName := make(map[string]string)
	for _, record := range records {
		latestSerialByCommonName[record.CommonName] = record.SerialNumber
		if record.TFAName != nil {
			latestTFANameByCommonName[record.CommonName] = *record.TFAName
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return result, fmt.Errorf("begin certificate metadata import: %w", err)
	}
	defer tx.Rollback()

	for _, record := range records {
		var exists bool
		if err := tx.QueryRowContext(
			ctx,
			`SELECT EXISTS(
				SELECT 1 FROM certificates
				WHERE serial_number = ? COLLATE NOCASE
			)`,
			record.SerialNumber,
		).Scan(&exists); err != nil {
			return CertificateImportResult{}, fmt.Errorf(
				"check certificate metadata by serial: %w",
				err,
			)
		}

		execResult, err := tx.ExecContext(
			ctx,
			`INSERT INTO certificates (
				common_name,
				serial_number,
				status,
				static_ip,
				technical_expires_at,
				revoked_at,
				created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(serial_number) DO UPDATE SET
				common_name = excluded.common_name,
				status = CASE
					WHEN certificates.archived_at IS NOT NULL THEN certificates.status
					ELSE excluded.status
				END,
					static_ip = COALESCE(
						excluded.static_ip,
						certificates.static_ip
					),
				technical_expires_at = excluded.technical_expires_at,
				revoked_at = excluded.revoked_at
			WHERE certificates.common_name IS NOT excluded.common_name
				OR (
					certificates.archived_at IS NULL
					AND certificates.status IS NOT excluded.status
				)
					OR (
						excluded.static_ip IS NOT NULL
						AND certificates.static_ip IS NOT excluded.static_ip
					)
				OR certificates.technical_expires_at IS NOT excluded.technical_expires_at
				OR certificates.revoked_at IS NOT excluded.revoked_at`,
			record.CommonName,
			record.SerialNumber,
			record.Status,
			nullableStringValue(record.StaticIP),
			record.TechnicalExpiresAt.UTC(),
			nullableTimeValue(record.RevokedAt),
			importedAt.UTC(),
		)
		if err != nil {
			return CertificateImportResult{}, fmt.Errorf(
				"upsert certificate metadata by serial: %w",
				err,
			)
		}

		rowsAffected, err := execResult.RowsAffected()
		if err != nil {
			return CertificateImportResult{}, fmt.Errorf(
				"read certificate metadata import result: %w",
				err,
			)
		}
		switch {
		case rowsAffected == 0:
			result.Unchanged++
		case rowsAffected == 1 && exists:
			result.Updated++
		case rowsAffected == 1:
			result.Inserted++
		default:
			return CertificateImportResult{}, fmt.Errorf(
				"certificate metadata upsert affected %d rows",
				rowsAffected,
			)
		}
	}

	for commonName, tfaName := range latestTFANameByCommonName {
		targetSerial := latestSerialByCommonName[commonName]
		var certificateID int64
		if err := tx.QueryRowContext(
			ctx,
			`SELECT id FROM certificates
			WHERE serial_number = ? COLLATE NOCASE`,
			targetSerial,
		).Scan(&certificateID); err != nil {
			return CertificateImportResult{}, fmt.Errorf(
				"read current certificate ID for 2FA identity metadata: %w",
				err,
			)
		}

		var databaseTFAName string
		err := tx.QueryRowContext(
			ctx,
			`SELECT tfa_name FROM totp_identities WHERE certificate_id = ?`,
			certificateID,
		).Scan(&databaseTFAName)
		if err == nil {
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return CertificateImportResult{}, fmt.Errorf(
				"read current certificate 2FA identity metadata: %w",
				err,
			)
		}
		if err := upsertTOTPIdentityMetadata(
			ctx,
			tx,
			certificateID,
			tfaName,
			"",
			importedAt,
		); err != nil {
			return CertificateImportResult{}, fmt.Errorf(
				"upsert certificate 2FA identity metadata: %w",
				err,
			)
		}
	}

	if err := tx.Commit(); err != nil {
		return CertificateImportResult{}, fmt.Errorf(
			"commit certificate metadata import: %w",
			err,
		)
	}
	return result, nil
}

func upsertTOTPIdentityMetadata(
	ctx context.Context,
	tx *sql.Tx,
	certificateID int64,
	tfaName string,
	issuer string,
	createdAt time.Time,
) error {
	if certificateID <= 0 || !ValidateCertificateCommonName(tfaName) {
		return errors.New("invalid 2FA identity metadata")
	}

	var identityID int64
	var existingCertificateID int64
	err := tx.QueryRowContext(
		ctx,
		`SELECT id, certificate_id
		FROM totp_identities
		WHERE tfa_name = ?`,
		tfaName,
	).Scan(&identityID, &existingCertificateID)
	if err == nil {
		if existingCertificateID != certificateID {
			var existingCommonName string
			var requestedCommonName string
			if err := tx.QueryRowContext(
				ctx,
				`SELECT common_name FROM certificates WHERE id = ?`,
				existingCertificateID,
			).Scan(&existingCommonName); err != nil {
				return err
			}
			if err := tx.QueryRowContext(
				ctx,
				`SELECT common_name FROM certificates WHERE id = ?`,
				certificateID,
			).Scan(&requestedCommonName); err != nil {
				return err
			}
			if existingCommonName != requestedCommonName {
				return errors.New("2FA identity is assigned to a different certificate name")
			}
		}
		var conflictingIdentityID int64
		conflictErr := tx.QueryRowContext(
			ctx,
			`SELECT id FROM totp_identities
			WHERE certificate_id = ? AND id <> ?`,
			certificateID,
			identityID,
		).Scan(&conflictingIdentityID)
		if conflictErr == nil {
			return errors.New("certificate already has different 2FA identity metadata")
		}
		if !errors.Is(conflictErr, sql.ErrNoRows) {
			return conflictErr
		}
		_, err = tx.ExecContext(
			ctx,
			`UPDATE totp_identities
			SET certificate_id = ?,
				issuer = CASE WHEN ? <> '' THEN ? ELSE issuer END,
				status = 'active'
			WHERE id = ?`,
			certificateID,
			issuer,
			issuer,
			identityID,
		)
		return err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	err = tx.QueryRowContext(
		ctx,
		`SELECT id FROM totp_identities WHERE certificate_id = ?`,
		certificateID,
	).Scan(&identityID)
	if err == nil {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE totp_identities
			SET tfa_name = ?,
				issuer = CASE WHEN ? <> '' THEN ? ELSE issuer END,
				status = 'active'
			WHERE id = ?`,
			tfaName,
			issuer,
			issuer,
			identityID,
		)
		return err
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		`INSERT INTO totp_identities (
			certificate_id,
			tfa_name,
			issuer,
			status,
			created_at
		) VALUES (?, ?, ?, 'active', ?)`,
		certificateID,
		tfaName,
		issuer,
		createdAt.UTC(),
	)
	return err
}

func nullableStringValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullableTimeValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}
