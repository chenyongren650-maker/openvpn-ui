package services

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxCompatibilityIndexSize = 64 * 1024 * 1024

var numericObjectIdentifierPattern = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+)+$`,
)

var indexSubjectObjectIdentifiers = map[string]string{
	"C":            "2.5.4.6",
	"ST":           "2.5.4.8",
	"L":            "2.5.4.7",
	"O":            "2.5.4.10",
	"OU":           "2.5.4.11",
	"CN":           "2.5.4.3",
	"serialNumber": "2.5.4.5",
	"street":       "2.5.4.9",
	"postalCode":   "2.5.4.17",
	"name":         "2.5.4.41",
	"givenName":    "2.5.4.42",
	"surname":      "2.5.4.4",
	"emailAddress": "1.2.840.113549.1.9.1",
	"UID":          "0.9.2342.19200300.100.1.1",
	"DC":           "0.9.2342.19200300.100.1.25",
}

type indexSubjectAttribute struct {
	ObjectIdentifier string
	Value            string
}

func (s *CertificateLifecycleService) normalizeLegacyIndexMetadata(
	state CertificateState,
	revokeCommand string,
) (bool, error) {
	certificatePath, err := s.revokeCertificatePath(
		state.CommonName,
		revokeCommand,
	)
	if err != nil {
		return false, err
	}
	certificate, err := readCertificate(certificatePath)
	if err != nil {
		return false, err
	}
	if certificate.Subject.CommonName != state.CommonName ||
		normalizeCertificateSerial(certificate.SerialNumber.Text(16)) !=
			normalizeCertificateSerial(state.SerialNumber) {
		return false, ErrCertificatePKIMismatch
	}

	indexInfo, err := os.Lstat(s.indexPath)
	if err != nil {
		return false, err
	}
	if !indexInfo.Mode().IsRegular() ||
		indexInfo.Mode()&os.ModeSymlink != 0 ||
		indexInfo.Size() > maxCompatibilityIndexSize {
		return false, errors.New("certificate index is not a safe regular file")
	}
	indexData, err := os.ReadFile(s.indexPath)
	if err != nil {
		return false, err
	}

	normalizedData, changed, err := normalizeLegacyIndexTarget(
		indexData,
		state,
		certificate,
	)
	if err != nil || !changed {
		return changed, err
	}
	if _, err := createIndexCompatibilityBackup(
		s.indexPath,
		indexData,
		state.SerialNumber,
		s.now().UTC(),
	); err != nil {
		return false, fmt.Errorf("back up certificate index: %w", err)
	}
	if err := replaceIndexAtomically(
		s.indexPath,
		normalizedData,
		indexInfo.Mode().Perm(),
	); err != nil {
		return false, fmt.Errorf("replace certificate index: %w", err)
	}
	return true, nil
}

func (s *CertificateLifecycleService) revokeCertificatePath(
	commonName string,
	revokeCommand string,
) (string, error) {
	switch revokeCommand {
	case "revoke":
		return filepath.Join(s.pkiDir, "issued", commonName+".crt"), nil
	case "revoke-renewed":
		return filepath.Join(
			s.pkiDir,
			"renewed",
			"issued",
			commonName+".crt",
		), nil
	default:
		return "", errors.New("unsupported Easy-RSA revoke command")
	}
}

func normalizeLegacyIndexTarget(
	indexData []byte,
	state CertificateState,
	certificate *x509.Certificate,
) ([]byte, bool, error) {
	if certificate == nil {
		return nil, false, errors.New("certificate identity is unavailable")
	}
	lines := bytes.SplitAfter(indexData, []byte{'\n'})
	targetIndex := -1
	normalizedLine := []byte(nil)
	for index, rawLine := range lines {
		line, lineEnding := splitIndexLineEnding(rawLine)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		fields := strings.Split(string(line), "\t")
		if len(fields) != 6 ||
			normalizeCertificateSerial(fields[3]) !=
				normalizeCertificateSerial(state.SerialNumber) {
			continue
		}
		if targetIndex >= 0 {
			return nil, false, errors.New(
				"certificate index contains duplicate target serial",
			)
		}
		if fields[0] != "V" && fields[0] != "E" {
			return nil, false, errors.New(
				"legacy certificate index target is not revocable",
			)
		}
		normalizedSubject, changed, err := normalizeLegacyIndexSubject(
			fields[5],
			state,
			certificate,
		)
		if err != nil {
			return nil, false, err
		}
		targetIndex = index
		if changed {
			fields[5] = normalizedSubject
			normalizedLine = append(
				[]byte(strings.Join(fields, "\t")),
				lineEnding...,
			)
		}
	}
	if targetIndex < 0 {
		return nil, false, errors.New(
			"certificate index target serial was not found",
		)
	}
	if normalizedLine == nil {
		return append([]byte(nil), indexData...), false, nil
	}
	lines[targetIndex] = normalizedLine
	return bytes.Join(lines, nil), true, nil
}

func splitIndexLineEnding(line []byte) ([]byte, []byte) {
	switch {
	case bytes.HasSuffix(line, []byte("\r\n")):
		return line[:len(line)-2], []byte("\r\n")
	case bytes.HasSuffix(line, []byte{'\n'}):
		return line[:len(line)-1], []byte{'\n'}
	default:
		return line, nil
	}
}

func normalizeLegacyIndexSubject(
	indexSubject string,
	state CertificateState,
	certificate *x509.Certificate,
) (string, bool, error) {
	legacyMarker := "/name=" + state.CommonName
	markerIndex := strings.LastIndex(indexSubject, legacyMarker)
	if markerIndex < 0 {
		return indexSubject, false, nil
	}
	certificateSubject := indexSubject[:markerIndex]
	legacySuffix := indexSubject[markerIndex:]
	if err := validateLegacyIndexMetadata(legacySuffix, state); err != nil {
		return "", false, err
	}
	indexAttributes, err := parseIndexSubjectAttributes(certificateSubject)
	if err != nil {
		return "", false, err
	}
	certificateAttributes := parsedCertificateSubjectAttributes(certificate)
	if len(indexAttributes) != len(certificateAttributes) {
		return "", false, ErrCertificatePKIMismatch
	}
	for index := range indexAttributes {
		if indexAttributes[index] != certificateAttributes[index] {
			return "", false, ErrCertificatePKIMismatch
		}
	}
	return certificateSubject, true, nil
}

func validateLegacyIndexMetadata(
	legacySuffix string,
	state CertificateState,
) error {
	parts, err := splitCertificateSubject(legacySuffix)
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found || seen[key] {
			return errors.New("legacy certificate metadata is malformed")
		}
		seen[key] = true
		switch key {
		case "name":
			if value != state.CommonName {
				return ErrCertificatePKIMismatch
			}
		case "LocalIP":
			if !legacyStaticIPMatches(value, state.StaticIP) {
				return ErrCertificatePKIMismatch
			}
		case "2FAName":
			if !legacyTFANameMatches(value, state.TFAName) {
				return ErrCertificatePKIMismatch
			}
		default:
			return errors.New("legacy certificate metadata contains an unsupported field")
		}
	}
	if !seen["name"] {
		return errors.New("legacy certificate metadata has no name")
	}
	return nil
}

func legacyStaticIPMatches(legacyValue string, databaseValue string) bool {
	if databaseValue != "" {
		return legacyValue == databaseValue
	}
	return legacyValue == "" ||
		strings.EqualFold(legacyValue, "dynamic.pool") ||
		strings.EqualFold(legacyValue, "none")
}

func legacyTFANameMatches(legacyValue string, databaseValue string) bool {
	if databaseValue != "" {
		return legacyValue == databaseValue
	}
	return legacyValue == "" || strings.EqualFold(legacyValue, "none")
}

func parseIndexSubjectAttributes(
	indexSubject string,
) ([]indexSubjectAttribute, error) {
	parts, err := splitCertificateSubject(indexSubject)
	if err != nil {
		return nil, err
	}
	attributes := make([]indexSubjectAttribute, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		key, value, found := strings.Cut(part, "=")
		if !found || key == "" {
			return nil, errors.New("certificate subject is malformed")
		}
		objectIdentifier, known := indexSubjectObjectIdentifiers[key]
		if !known {
			if !numericObjectIdentifierPattern.MatchString(key) {
				return nil, errors.New(
					"certificate subject contains an unsupported attribute",
				)
			}
			objectIdentifier = key
		}
		attributes = append(attributes, indexSubjectAttribute{
			ObjectIdentifier: objectIdentifier,
			Value:            value,
		})
	}
	if len(attributes) == 0 {
		return nil, errors.New("certificate subject is empty")
	}
	return attributes, nil
}

func parsedCertificateSubjectAttributes(
	certificate *x509.Certificate,
) []indexSubjectAttribute {
	attributes := make(
		[]indexSubjectAttribute,
		0,
		len(certificate.Subject.Names),
	)
	for _, attribute := range certificate.Subject.Names {
		attributes = append(attributes, indexSubjectAttribute{
			ObjectIdentifier: attribute.Type.String(),
			Value:            fmt.Sprint(attribute.Value),
		})
	}
	return attributes
}

func createIndexCompatibilityBackup(
	indexPath string,
	indexData []byte,
	serialNumber string,
	backupTime time.Time,
) (string, error) {
	backupDirectory := filepath.Join(
		filepath.Dir(indexPath),
		"index-compatibility-backups",
	)
	if err := ensureSecureBackupDirectory(backupDirectory); err != nil {
		return "", err
	}
	timestamp := backupTime.UTC().Format("20060102T150405.000000000Z")
	temporaryFile, err := os.CreateTemp(
		backupDirectory,
		".index.txt-"+timestamp+"-"+normalizeCertificateSerial(serialNumber)+"-*.tmp",
	)
	if err != nil {
		return "", err
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	if err := temporaryFile.Chmod(0o600); err != nil {
		temporaryFile.Close()
		return "", err
	}
	if _, err := temporaryFile.Write(indexData); err != nil {
		temporaryFile.Close()
		return "", err
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return "", err
	}
	if err := temporaryFile.Close(); err != nil {
		return "", err
	}
	backupPath := strings.TrimSuffix(temporaryPath, ".tmp") + ".bak"
	if err := os.Rename(temporaryPath, backupPath); err != nil {
		return "", err
	}
	if err := syncIndexDirectory(backupDirectory); err != nil {
		return "", err
	}
	return backupPath, nil
}

func ensureSecureBackupDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("certificate index backup path is not a safe directory")
	}
	return os.Chmod(path, 0o700)
}

func replaceIndexAtomically(
	indexPath string,
	indexData []byte,
	mode os.FileMode,
) error {
	directory := filepath.Dir(indexPath)
	temporaryFile, err := os.CreateTemp(directory, ".index-compatibility-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	if err := temporaryFile.Chmod(mode); err != nil {
		temporaryFile.Close()
		return err
	}
	if _, err := temporaryFile.Write(indexData); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return err
	}
	if err := temporaryFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, indexPath); err != nil {
		return err
	}
	return syncIndexDirectory(directory)
}

func syncIndexDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
