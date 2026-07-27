package services

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	PermissionTypeNormal     = "normal"
	PermissionTypeRestricted = "restricted"

	restrictedPoolPrefix       = "10.9.5."
	restrictedPoolFirstHost    = 10
	restrictedPoolLastHost     = 254
	maxStaticClientFileSize    = 4 * 1024
	maxIPPPersistenceFileSize  = 1024 * 1024
	maxIPPPersistenceLineSize  = 1024
	maxManagementStatusSize    = 1024 * 1024
	maxManagementStatusLine    = 16 * 1024
	defaultAllocationMITimeout = 5 * time.Second
)

var (
	ErrRestrictedIPInvalidInput       = errors.New("restricted IP allocation input is invalid")
	ErrRestrictedIPDataSource         = errors.New("restricted IP allocation data source is unavailable or invalid")
	ErrRestrictedIPPoolExhausted      = errors.New("restricted IP allocation pool is exhausted")
	ErrRestrictedIPReservationMissing = errors.New("restricted IP allocation reservation was not found")
	ErrRestrictedIPReservationState   = errors.New("restricted IP allocation reservation state is invalid")
	ErrRestrictedIPConflict           = errors.New("restricted IP allocation conflicts with existing state")
)

type RestrictedIPReservation struct {
	ID              int64
	IPAddress       string
	CertificateName string
	RequestID       string
	Status          string
}

type OnlineIPv4Source interface {
	OnlineIPv4(context.Context) (map[string]struct{}, error)
}

type RestrictedIPAllocationConfig struct {
	StaticClientsDir   string
	IPPPersistencePath string
	ManagementNetwork  string
	ManagementAddress  string
	ManagementTimeout  time.Duration
	OnlineIPSource     OnlineIPv4Source
}

type RestrictedIPAllocationService struct {
	db                 *sql.DB
	staticClientsDir   string
	ippPersistencePath string
	onlineIPSource     OnlineIPv4Source
	now                func() time.Time
}

func NewRestrictedIPAllocationService(
	db *sql.DB,
	config RestrictedIPAllocationConfig,
) (*RestrictedIPAllocationService, error) {
	if db == nil {
		return nil, errors.New("restricted IP allocation database is nil")
	}
	staticClientsDir, err := cleanAbsolutePath(config.StaticClientsDir)
	if err != nil {
		return nil, fmt.Errorf("resolve static clients directory: %w", err)
	}
	ippPersistencePath, err := cleanAbsolutePath(config.IPPPersistencePath)
	if err != nil {
		return nil, fmt.Errorf("resolve ipp.txt path: %w", err)
	}

	onlineIPSource := config.OnlineIPSource
	if onlineIPSource == nil {
		timeout := config.ManagementTimeout
		if timeout <= 0 {
			timeout = defaultAllocationMITimeout
		}
		if strings.TrimSpace(config.ManagementNetwork) == "" ||
			strings.TrimSpace(config.ManagementAddress) == "" {
			return nil, errors.New("OpenVPN management interface is not configured")
		}
		onlineIPSource = managementOnlineIPv4Source{
			network: config.ManagementNetwork,
			address: config.ManagementAddress,
			timeout: timeout,
		}
	}

	return &RestrictedIPAllocationService{
		db:                 db,
		staticClientsDir:   staticClientsDir,
		ippPersistencePath: ippPersistencePath,
		onlineIPSource:     onlineIPSource,
		now:                func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *RestrictedIPAllocationService) Reserve(
	ctx context.Context,
	certificateName string,
	requestID string,
) (RestrictedIPReservation, error) {
	certificateName = strings.TrimSpace(certificateName)
	requestID = strings.TrimSpace(requestID)
	if !ValidateCertificateCommonName(certificateName) ||
		!auditRequestIDPattern.MatchString(requestID) {
		return RestrictedIPReservation{}, ErrRestrictedIPInvalidInput
	}

	existing, found, err := findReusableReservation(
		ctx,
		s.db,
		certificateName,
	)
	if err != nil {
		return RestrictedIPReservation{}, fmt.Errorf(
			"%w: read existing reservation",
			ErrRestrictedIPDataSource,
		)
	}
	if found {
		return existing, nil
	}

	externalOccupied, err := s.readExternalOccupiedAddresses(ctx)
	if err != nil {
		return RestrictedIPReservation{}, err
	}

	for attempt := 0; attempt <= restrictedPoolLastHost-restrictedPoolFirstHost+1; attempt++ {
		reservation, retry, err := s.reserveAttempt(
			ctx,
			certificateName,
			requestID,
			externalOccupied,
		)
		if err == nil {
			return reservation, nil
		}
		if !retry {
			return RestrictedIPReservation{}, err
		}
	}
	return RestrictedIPReservation{}, ErrRestrictedIPConflict
}

func (s *RestrictedIPAllocationService) reserveAttempt(
	ctx context.Context,
	certificateName string,
	requestID string,
	externalOccupied map[string]struct{},
) (RestrictedIPReservation, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		if isRetryableSQLiteError(err) {
			return RestrictedIPReservation{}, true, err
		}
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: begin reservation transaction",
			ErrRestrictedIPDataSource,
		)
	}
	defer tx.Rollback()

	existing, found, err := findReusableReservation(ctx, tx, certificateName)
	if err != nil {
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: read reservation transaction state",
			ErrRestrictedIPDataSource,
		)
	}
	if found {
		if err := tx.Commit(); err != nil {
			return RestrictedIPReservation{}, isRetryableSQLiteError(err), err
		}
		return existing, false, nil
	}

	occupied := cloneAddressSet(externalOccupied)
	if err := readDatabaseOccupiedAddresses(ctx, tx, occupied); err != nil {
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: read database allocation state",
			ErrRestrictedIPDataSource,
		)
	}
	candidate, found := firstAvailableRestrictedAddress(occupied)
	if !found {
		return RestrictedIPReservation{}, false, ErrRestrictedIPPoolExhausted
	}

	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `INSERT INTO ip_allocation_reservations (
		ip_address, certificate_name, request_id, status, reserved_at,
		completed_at, released_at, error_summary
	) VALUES (?, ?, ?, 'reserved', ?, NULL, NULL, '')`,
		candidate,
		certificateName,
		requestID,
		now,
	)
	if err != nil {
		if isRetryableSQLiteError(err) {
			return RestrictedIPReservation{}, true, err
		}
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: persist address reservation",
			ErrRestrictedIPDataSource,
		)
	}
	reservationID, err := result.LastInsertId()
	if err != nil {
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: read address reservation ID",
			ErrRestrictedIPDataSource,
		)
	}
	if err := tx.Commit(); err != nil {
		if isRetryableSQLiteError(err) {
			return RestrictedIPReservation{}, true, err
		}
		return RestrictedIPReservation{}, false, fmt.Errorf(
			"%w: commit address reservation",
			ErrRestrictedIPDataSource,
		)
	}
	return RestrictedIPReservation{
		ID:              reservationID,
		IPAddress:       candidate,
		CertificateName: certificateName,
		RequestID:       requestID,
		Status:          "reserved",
	}, false, nil
}

func (s *RestrictedIPAllocationService) Release(
	ctx context.Context,
	reservationID int64,
	errorSummary string,
) error {
	if reservationID <= 0 || !validAllocationErrorSummary(errorSummary) {
		return ErrRestrictedIPInvalidInput
	}
	result, err := s.db.ExecContext(ctx, `UPDATE ip_allocation_reservations
		SET status = 'released', released_at = ?, error_summary = ?
		WHERE id = ? AND status = 'reserved'`,
		s.now().UTC(),
		errorSummary,
		reservationID,
	)
	if err != nil {
		return fmt.Errorf("release restricted IP reservation: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read restricted IP release result: %w", err)
	}
	if rowsAffected == 1 {
		return nil
	}
	var status string
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT status FROM ip_allocation_reservations WHERE id = ?`,
		reservationID,
	).Scan(&status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRestrictedIPReservationMissing
		}
		return err
	}
	if status == "released" {
		return nil
	}
	return ErrRestrictedIPReservationState
}

func (s *RestrictedIPAllocationService) MarkRecoveryRequired(
	ctx context.Context,
	reservationID int64,
	errorSummary string,
) error {
	if reservationID <= 0 || !validAllocationErrorSummary(errorSummary) {
		return ErrRestrictedIPInvalidInput
	}
	result, err := s.db.ExecContext(ctx, `UPDATE ip_allocation_reservations
		SET error_summary = ?
		WHERE id = ? AND status = 'reserved'`,
		errorSummary,
		reservationID,
	)
	if err != nil {
		return fmt.Errorf("mark restricted IP reservation recovery: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return ErrRestrictedIPReservationState
	}
	return nil
}

func (s *RestrictedIPAllocationService) Complete(
	ctx context.Context,
	reservationID int64,
	certificateID int64,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.completeReservationTx(
		ctx,
		tx,
		reservationID,
		certificateID,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *RestrictedIPAllocationService) completeReservationTx(
	ctx context.Context,
	tx *sql.Tx,
	reservationID int64,
	certificateID int64,
) error {
	if tx == nil || reservationID <= 0 || certificateID <= 0 {
		return ErrRestrictedIPInvalidInput
	}
	var reservation RestrictedIPReservation
	if err := tx.QueryRowContext(ctx, `SELECT
		id, ip_address, certificate_name, request_id, status
		FROM ip_allocation_reservations WHERE id = ?`,
		reservationID,
	).Scan(
		&reservation.ID,
		&reservation.IPAddress,
		&reservation.CertificateName,
		&reservation.RequestID,
		&reservation.Status,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRestrictedIPReservationMissing
		}
		return err
	}
	if reservation.Status == "released" {
		return ErrRestrictedIPReservationState
	}

	now := s.now().UTC()
	if _, err := tx.ExecContext(ctx, `INSERT INTO ip_allocations (
		ip_address, pool_name, certificate_id, status,
		allocated_at, pending_release_at, released_at, notes
	) VALUES (?, 'restricted', ?, 'allocated', ?, NULL, NULL, '')
	ON CONFLICT(certificate_id) DO NOTHING`,
		reservation.IPAddress,
		certificateID,
		now,
	); err != nil {
		return fmt.Errorf("%w: create final IP allocation", ErrRestrictedIPConflict)
	}

	var allocatedIP, allocationStatus string
	if err := tx.QueryRowContext(ctx, `SELECT ip_address, status
		FROM ip_allocations WHERE certificate_id = ?`,
		certificateID,
	).Scan(&allocatedIP, &allocationStatus); err != nil {
		return fmt.Errorf("verify final IP allocation: %w", err)
	}
	if allocatedIP != reservation.IPAddress || allocationStatus != "allocated" {
		return ErrRestrictedIPConflict
	}

	if reservation.Status == "completed" {
		return nil
	}
	result, err := tx.ExecContext(ctx, `UPDATE ip_allocation_reservations
		SET status = 'completed', completed_at = ?, error_summary = ''
		WHERE id = ? AND status = 'reserved'`,
		now,
		reservationID,
	)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected != 1 {
		return ErrRestrictedIPReservationState
	}
	return nil
}

func (s *RestrictedIPAllocationService) readExternalOccupiedAddresses(
	ctx context.Context,
) (map[string]struct{}, error) {
	occupied, err := readStaticClientAddresses(s.staticClientsDir)
	if err != nil {
		return nil, fmt.Errorf("%w: staticclients", ErrRestrictedIPDataSource)
	}
	ippAddresses, err := readIPPPersistenceAddresses(s.ippPersistencePath)
	if err != nil {
		return nil, fmt.Errorf("%w: ipp.txt", ErrRestrictedIPDataSource)
	}
	mergeAddressSets(occupied, ippAddresses)

	onlineAddresses, err := s.onlineIPSource.OnlineIPv4(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: management interface", ErrRestrictedIPDataSource)
	}
	for address := range onlineAddresses {
		if _, err := canonicalIPv4(address); err != nil {
			return nil, fmt.Errorf("%w: management interface address", ErrRestrictedIPDataSource)
		}
		occupied[address] = struct{}{}
	}
	return occupied, nil
}

type reservationQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func findReusableReservation(
	ctx context.Context,
	db reservationQueryer,
	certificateName string,
) (RestrictedIPReservation, bool, error) {
	var reservation RestrictedIPReservation
	err := db.QueryRowContext(ctx, `SELECT
		id, ip_address, certificate_name, request_id, status
	FROM ip_allocation_reservations
	WHERE certificate_name = ? COLLATE NOCASE
		AND status IN ('reserved', 'completed')
	ORDER BY CASE status WHEN 'reserved' THEN 0 ELSE 1 END, id DESC
	LIMIT 1`,
		certificateName,
	).Scan(
		&reservation.ID,
		&reservation.IPAddress,
		&reservation.CertificateName,
		&reservation.RequestID,
		&reservation.Status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return RestrictedIPReservation{}, false, nil
	}
	if err != nil {
		return RestrictedIPReservation{}, false, err
	}
	return reservation, true, nil
}

type addressRowsQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readDatabaseOccupiedAddresses(
	ctx context.Context,
	db addressRowsQueryer,
	occupied map[string]struct{},
) error {
	queries := []string{
		`SELECT static_ip FROM certificates
			WHERE static_ip IS NOT NULL AND trim(static_ip) <> ''`,
		`SELECT ip_address FROM ip_allocations
			WHERE status IN ('allocated', 'pending_release')`,
		`SELECT ip_address FROM ip_allocation_reservations
			WHERE status = 'reserved'`,
	}
	for _, query := range queries {
		rows, err := db.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		for rows.Next() {
			var address string
			if err := rows.Scan(&address); err != nil {
				rows.Close()
				return err
			}
			address, err = canonicalIPv4(strings.TrimSpace(address))
			if err != nil {
				rows.Close()
				return err
			}
			occupied[address] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}

func readStaticClientAddresses(directory string) (map[string]struct{}, error) {
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 ||
		!directoryInfo.IsDir() {
		return nil, errors.New("static clients path is not a directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	occupied := make(map[string]struct{})
	for _, entry := range entries {
		if !ValidateCertificateCommonName(entry.Name()) {
			return nil, errors.New("static client filename is invalid")
		}
		path := filepath.Join(directory, entry.Name())
		data, err := readBoundedRegularFile(path, maxStaticClientFileSize)
		if err != nil {
			return nil, err
		}
		address, err := parseStaticClientAddress(data)
		if err != nil {
			return nil, err
		}
		if _, duplicate := occupied[address]; duplicate {
			return nil, errors.New("duplicate static client address")
		}
		occupied[address] = struct{}{}
	}
	return occupied, nil
}

func parseStaticClientAddress(data []byte) (string, error) {
	content := strings.TrimSuffix(string(data), "\n")
	content = strings.TrimSuffix(content, "\r")
	if content == "" || strings.ContainsAny(content, "\r\n\x00") {
		return "", errors.New("static client configuration is invalid")
	}
	fields := strings.Fields(content)
	if len(fields) != 3 || fields[0] != "ifconfig-push" {
		return "", errors.New("static client configuration is invalid")
	}
	address, err := canonicalIPv4(fields[1])
	if err != nil {
		return "", err
	}
	maskIP := net.ParseIP(fields[2])
	if maskIP == nil || maskIP.To4() == nil {
		return "", errors.New("static client netmask is invalid")
	}
	ones, bits := net.IPMask(maskIP.To4()).Size()
	if bits != 32 || ones <= 0 {
		return "", errors.New("static client netmask is invalid")
	}
	return address, nil
}

func readIPPPersistenceAddresses(path string) (map[string]struct{}, error) {
	data, err := readBoundedRegularFile(path, maxIPPPersistenceFileSize)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), maxIPPPersistenceLineSize)
	names := make(map[string]struct{})
	addresses := make(map[string]struct{})
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || strings.ContainsRune(line, '\x00') {
			return nil, errors.New("ipp.txt contains an invalid line")
		}
		fields := strings.Split(line, ",")
		if len(fields) != 2 ||
			fields[0] != strings.TrimSpace(fields[0]) ||
			fields[1] != strings.TrimSpace(fields[1]) ||
			!ValidateCertificateCommonName(fields[0]) {
			return nil, errors.New("ipp.txt contains an invalid record")
		}
		address, err := canonicalIPv4(fields[1])
		if err != nil {
			return nil, err
		}
		normalizedName := strings.ToLower(fields[0])
		if _, duplicate := names[normalizedName]; duplicate {
			return nil, errors.New("ipp.txt contains a duplicate certificate")
		}
		if _, duplicate := addresses[address]; duplicate {
			return nil, errors.New("ipp.txt contains a duplicate address")
		}
		names[normalizedName] = struct{}{}
		addresses[address] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return addresses, nil
}

func readBoundedRegularFile(path string, maximumSize int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() ||
		before.Size() > maximumSize {
		return nil, errors.New("file is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximumSize {
		return nil, errors.New("file exceeds maximum size")
	}
	return data, nil
}

func firstAvailableRestrictedAddress(
	occupied map[string]struct{},
) (string, bool) {
	for host := restrictedPoolFirstHost; host <= restrictedPoolLastHost; host++ {
		address := fmt.Sprintf("%s%d", restrictedPoolPrefix, host)
		if _, exists := occupied[address]; !exists {
			return address, true
		}
	}
	return "", false
}

func canonicalIPv4(value string) (string, error) {
	parsed := net.ParseIP(value)
	if parsed == nil || parsed.To4() == nil || parsed.To4().String() != value {
		return "", errors.New("IPv4 address is invalid")
	}
	return value, nil
}

func cloneAddressSet(source map[string]struct{}) map[string]struct{} {
	cloned := make(map[string]struct{}, len(source))
	mergeAddressSets(cloned, source)
	return cloned
}

func mergeAddressSets(destination, source map[string]struct{}) {
	for address := range source {
		destination[address] = struct{}{}
	}
}

func validAllocationErrorSummary(value string) bool {
	return value == "" || auditErrorSummaryPattern.MatchString(value)
}

func isRetryableSQLiteError(err error) bool {
	var sqliteError sqlite3.Error
	if !errors.As(err, &sqliteError) {
		return false
	}
	return sqliteError.Code == sqlite3.ErrBusy ||
		sqliteError.Code == sqlite3.ErrLocked ||
		sqliteError.Code == sqlite3.ErrConstraint
}

type managementOnlineIPv4Source struct {
	network string
	address string
	timeout time.Duration
}

func (s managementOnlineIPv4Source) OnlineIPv4(
	ctx context.Context,
) (map[string]struct{}, error) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultAllocationMITimeout
	}
	commandContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	connection, err := (&net.Dialer{}).DialContext(
		commandContext,
		s.network,
		s.address,
	)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if deadline, ok := commandContext.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stopCancellation := context.AfterFunc(commandContext, func() {
		_ = connection.Close()
	})
	defer stopCancellation()

	reader := bufio.NewReaderSize(connection, maxManagementStatusLine)
	if _, err := readManagementLine(reader); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(connection, "status 2\n"); err != nil {
		return nil, err
	}

	lines := make([]string, 0)
	totalSize := 0
	for {
		line, err := readManagementLine(reader)
		if err != nil {
			return nil, err
		}
		totalSize += len(line)
		if totalSize > maxManagementStatusSize {
			return nil, errors.New("management status response is too large")
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "END" {
			break
		}
		if strings.HasPrefix(line, "ERROR:") {
			return nil, errors.New("management status command failed")
		}
		lines = append(lines, line)
	}
	return parseManagementStatusIPv4(lines)
}

func readManagementLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxManagementStatusLine {
		return "", errors.New("management response line is too large")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func parseManagementStatusIPv4(lines []string) (map[string]struct{}, error) {
	addresses := make(map[string]struct{})
	for _, line := range lines {
		if line == "" {
			return nil, errors.New("management status contains an empty line")
		}
		reader := csv.NewReader(strings.NewReader(line))
		reader.FieldsPerRecord = -1
		fields, err := reader.Read()
		if err != nil || len(fields) == 0 {
			return nil, errors.New("management status CSV is invalid")
		}
		var virtualAddress string
		switch fields[0] {
		case "CLIENT_LIST":
			if len(fields) < 4 {
				return nil, errors.New("management client record is incomplete")
			}
			virtualAddress = fields[3]
		case "ROUTING_TABLE":
			if len(fields) < 2 {
				return nil, errors.New("management routing record is incomplete")
			}
			virtualAddress = fields[1]
		default:
			continue
		}
		virtualAddress = strings.TrimSpace(virtualAddress)
		if virtualAddress == "" {
			continue
		}
		parsed := net.ParseIP(virtualAddress)
		if parsed == nil {
			return nil, errors.New("management virtual address is invalid")
		}
		if parsed.To4() == nil {
			continue
		}
		if parsed.To4().String() != virtualAddress {
			return nil, errors.New("management IPv4 address is not canonical")
		}
		addresses[virtualAddress] = struct{}{}
	}
	return addresses, nil
}
