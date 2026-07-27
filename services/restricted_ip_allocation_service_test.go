package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/d3vilh/openvpn-ui/migrations"
)

type staticOnlineIPv4Source struct {
	addresses map[string]struct{}
	err       error
}

func (s staticOnlineIPv4Source) OnlineIPv4(
	context.Context,
) (map[string]struct{}, error) {
	if s.err != nil {
		return nil, s.err
	}
	return cloneAddressSet(s.addresses), nil
}

func TestRestrictedIPAllocationChecksEveryRequiredSource(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	writeTestFile(
		t,
		filepath.Join(fixture.staticClientsDir, "static-client"),
		"ifconfig-push 10.9.5.10 255.255.255.0\n",
	)
	writeTestFile(
		t,
		fixture.ippPath,
		"ipp-client,10.9.5.11\n",
	)
	insertTestCertificate(t, fixture.db, 1, "database-client", "A1", "10.9.5.12")
	insertTestCertificate(t, fixture.db, 2, "allocation-client", "A2", "")
	if _, err := fixture.db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status
	) VALUES ('10.9.5.13', 2, 'allocated')`); err != nil {
		t.Fatalf("seed allocated address: %v", err)
	}
	if _, err := fixture.db.Exec(`INSERT INTO ip_allocation_reservations (
		ip_address, certificate_name, request_id, status
	) VALUES ('10.9.5.14', 'reserved-client', 'existing-request', 'reserved')`); err != nil {
		t.Fatalf("seed reservation: %v", err)
	}
	fixture.service.onlineIPSource = staticOnlineIPv4Source{
		addresses: map[string]struct{}{"10.9.5.15": {}},
	}

	reservation, err := fixture.service.Reserve(
		context.Background(),
		"new-restricted-client",
		"request-all-sources",
	)
	if err != nil {
		t.Fatalf("reserve restricted address: %v", err)
	}
	if reservation.IPAddress != "10.9.5.16" {
		t.Fatalf("reserved address = %s, want 10.9.5.16", reservation.IPAddress)
	}
}

func TestRestrictedIPAllocationKeepsPendingReleaseAndReusesReleased(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	insertTestCertificate(t, fixture.db, 1, "pending-client", "B1", "")
	insertTestCertificate(t, fixture.db, 2, "released-client", "B2", "")
	if _, err := fixture.db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status, pending_release_at
	) VALUES ('10.9.5.10', 1, 'pending_release', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("seed pending release allocation: %v", err)
	}
	if _, err := fixture.db.Exec(`INSERT INTO ip_allocations (
		ip_address, certificate_id, status, released_at
	) VALUES ('10.9.5.11', 2, 'released', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("seed released allocation: %v", err)
	}

	reservation, err := fixture.service.Reserve(
		context.Background(),
		"new-client",
		"request-release-state",
	)
	if err != nil {
		t.Fatalf("reserve restricted address: %v", err)
	}
	if reservation.IPAddress != "10.9.5.11" {
		t.Fatalf("reserved address = %s, want released 10.9.5.11", reservation.IPAddress)
	}
}

func TestRestrictedIPAllocationRetryReusesOriginalReservation(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	first, err := fixture.service.Reserve(
		context.Background(),
		"retry-client",
		"request-first",
	)
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	fixture.service.onlineIPSource = staticOnlineIPv4Source{
		err: errors.New("management interface should not be read during retry"),
	}
	second, err := fixture.service.Reserve(
		context.Background(),
		"retry-client",
		"request-second",
	)
	if err != nil {
		t.Fatalf("retry reservation: %v", err)
	}
	if second.ID != first.ID || second.IPAddress != first.IPAddress {
		t.Fatalf("retry reservation = %+v, want original %+v", second, first)
	}
}

func TestRestrictedIPAllocationTwoServiceInstancesAreConcurrentSafe(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	secondDB := openRestrictedIPTestDatabase(t, fixture.databasePath)
	defer secondDB.Close()
	secondService, err := NewRestrictedIPAllocationService(
		secondDB,
		fixture.config(staticOnlineIPv4Source{addresses: map[string]struct{}{}}),
	)
	if err != nil {
		t.Fatalf("create second allocation service: %v", err)
	}

	const reservationCount = 24
	addresses := make(chan string, reservationCount)
	failures := make(chan error, reservationCount)
	var waitGroup sync.WaitGroup
	for index := 0; index < reservationCount; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			service := fixture.service
			if index%2 == 1 {
				service = secondService
			}
			reservation, err := service.Reserve(
				context.Background(),
				fmt.Sprintf("concurrent-client-%02d", index),
				fmt.Sprintf("concurrent-request-%02d", index),
			)
			if err != nil {
				failures <- err
				return
			}
			addresses <- reservation.IPAddress
		}(index)
	}
	waitGroup.Wait()
	close(addresses)
	close(failures)
	for err := range failures {
		t.Errorf("concurrent reservation: %v", err)
	}
	if t.Failed() {
		return
	}

	got := make([]string, 0, reservationCount)
	seen := make(map[string]struct{}, reservationCount)
	for address := range addresses {
		if _, duplicate := seen[address]; duplicate {
			t.Fatalf("duplicate concurrent address: %s", address)
		}
		seen[address] = struct{}{}
		got = append(got, address)
	}
	if len(got) != reservationCount {
		t.Fatalf("reservation count = %d, want %d", len(got), reservationCount)
	}
	sort.Strings(got)
	for host := restrictedPoolFirstHost; host < restrictedPoolFirstHost+reservationCount; host++ {
		expected := fmt.Sprintf("10.9.5.%d", host)
		if _, exists := seen[expected]; !exists {
			t.Fatalf("expected concurrent allocation %s, got %v", expected, got)
		}
	}
}

func TestRestrictedIPAllocationCompletionAndReleaseAreIdempotent(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	reservation, err := fixture.service.Reserve(
		context.Background(),
		"complete-client",
		"request-complete",
	)
	if err != nil {
		t.Fatalf("reserve address: %v", err)
	}
	insertTestCertificate(
		t,
		fixture.db,
		1,
		"complete-client",
		"C1",
		reservation.IPAddress,
	)
	if err := fixture.service.Complete(context.Background(), reservation.ID, 1); err != nil {
		t.Fatalf("complete reservation: %v", err)
	}
	if err := fixture.service.Complete(context.Background(), reservation.ID, 1); err != nil {
		t.Fatalf("repeat completion: %v", err)
	}

	var reservationStatus, allocationStatus string
	if err := fixture.db.QueryRow(`SELECT status
		FROM ip_allocation_reservations WHERE id = ?`,
		reservation.ID,
	).Scan(&reservationStatus); err != nil {
		t.Fatalf("read reservation status: %v", err)
	}
	if err := fixture.db.QueryRow(`SELECT status
		FROM ip_allocations WHERE certificate_id = 1`,
	).Scan(&allocationStatus); err != nil {
		t.Fatalf("read allocation status: %v", err)
	}
	if reservationStatus != "completed" || allocationStatus != "allocated" {
		t.Fatalf(
			"reservation status = %s, allocation status = %s",
			reservationStatus,
			allocationStatus,
		)
	}
	if err := fixture.service.Release(
		context.Background(),
		reservation.ID,
		"creation_failed",
	); !errors.Is(err, ErrRestrictedIPReservationState) {
		t.Fatalf("release completed reservation error = %v", err)
	}

	released, err := fixture.service.Reserve(
		context.Background(),
		"released-client",
		"request-release",
	)
	if err != nil {
		t.Fatalf("reserve releasable address: %v", err)
	}
	if err := fixture.service.Release(
		context.Background(),
		released.ID,
		"creation_failed",
	); err != nil {
		t.Fatalf("release reservation: %v", err)
	}
	if err := fixture.service.Release(
		context.Background(),
		released.ID,
		"creation_failed",
	); err != nil {
		t.Fatalf("repeat release: %v", err)
	}
}

func TestRestrictedIPAllocationFailsClosedForInvalidSources(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *restrictedIPTestFixture)
	}{
		{
			name: "management unavailable",
			prepare: func(_ *testing.T, fixture *restrictedIPTestFixture) {
				fixture.service.onlineIPSource = staticOnlineIPv4Source{
					err: errors.New("management timeout"),
				}
			},
		},
		{
			name: "management malformed address",
			prepare: func(_ *testing.T, fixture *restrictedIPTestFixture) {
				fixture.service.onlineIPSource = staticOnlineIPv4Source{
					addresses: map[string]struct{}{"not-an-ip": {}},
				}
			},
		},
		{
			name: "malformed static client",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				writeTestFile(
					t,
					filepath.Join(fixture.staticClientsDir, "bad-client"),
					"iroute 10.9.5.10 255.255.255.0\n",
				)
			},
		},
		{
			name: "oversized static client",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				writeTestFile(
					t,
					filepath.Join(fixture.staticClientsDir, "large-client"),
					string(make([]byte, maxStaticClientFileSize+1)),
				)
			},
		},
		{
			name: "static client symlink",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				target := filepath.Join(fixture.root, "symlink-target")
				writeTestFile(t, target, "ifconfig-push 10.9.5.10 255.255.255.0\n")
				if err := os.Symlink(
					target,
					filepath.Join(fixture.staticClientsDir, "linked-client"),
				); err != nil {
					t.Fatalf("create static client symlink: %v", err)
				}
			},
		},
		{
			name: "static clients directory symlink",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				target := filepath.Join(fixture.root, "linked-staticclients")
				if err := os.MkdirAll(target, 0o700); err != nil {
					t.Fatalf("create linked static clients target: %v", err)
				}
				if err := os.Remove(fixture.staticClientsDir); err != nil {
					t.Fatalf("remove static clients directory: %v", err)
				}
				if err := os.Symlink(target, fixture.staticClientsDir); err != nil {
					t.Fatalf("link static clients directory: %v", err)
				}
			},
		},
		{
			name: "malformed ipp record",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				writeTestFile(t, fixture.ippPath, "../bad,10.9.5.10\n")
			},
		},
		{
			name: "duplicate ipp address",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				writeTestFile(
					t,
					fixture.ippPath,
					"client-a,10.9.5.10\nclient-b,10.9.5.10\n",
				)
			},
		},
		{
			name: "oversized ipp file",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				writeTestFile(
					t,
					fixture.ippPath,
					string(make([]byte, maxIPPPersistenceFileSize+1)),
				)
			},
		},
		{
			name: "ipp symlink",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				target := filepath.Join(fixture.root, "ipp-target")
				writeTestFile(t, target, "linked-client,10.9.5.10\n")
				if err := os.Remove(fixture.ippPath); err != nil {
					t.Fatalf("remove ipp file: %v", err)
				}
				if err := os.Symlink(target, fixture.ippPath); err != nil {
					t.Fatalf("create ipp symlink: %v", err)
				}
			},
		},
		{
			name: "invalid database address",
			prepare: func(t *testing.T, fixture *restrictedIPTestFixture) {
				insertTestCertificate(
					t,
					fixture.db,
					1,
					"invalid-address-client",
					"BAD1",
					"not-an-ip",
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRestrictedIPTestFixture(t)
			defer fixture.close()
			test.prepare(t, fixture)

			_, err := fixture.service.Reserve(
				context.Background(),
				"fail-closed-client",
				"request-fail-closed",
			)
			if !errors.Is(err, ErrRestrictedIPDataSource) {
				t.Fatalf("reservation error = %v, want data source failure", err)
			}
			var reservationCount int
			if queryErr := fixture.db.QueryRow(
				`SELECT COUNT(*) FROM ip_allocation_reservations`,
			).Scan(&reservationCount); queryErr != nil {
				t.Fatalf("count reservations: %v", queryErr)
			}
			if reservationCount != 0 {
				t.Fatalf("reservation count = %d, want 0", reservationCount)
			}
		})
	}
}

func TestRestrictedIPAllocationRejectsInjectionAndPathTraversal(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	for _, certificateName := range []string{
		"../escape",
		"client;touch-pwned",
		"client\nother",
		"/absolute",
	} {
		if _, err := fixture.service.Reserve(
			context.Background(),
			certificateName,
			"request-invalid-name",
		); !errors.Is(err, ErrRestrictedIPInvalidInput) {
			t.Fatalf("certificate name %q error = %v", certificateName, err)
		}
	}
	if _, err := fixture.service.Reserve(
		context.Background(),
		"valid-client",
		"request id with spaces",
	); !errors.Is(err, ErrRestrictedIPInvalidInput) {
		t.Fatalf("invalid request ID error = %v", err)
	}
}

func TestRestrictedIPAllocationReportsPoolExhaustion(t *testing.T) {
	fixture := newRestrictedIPTestFixture(t)
	defer fixture.close()

	online := make(map[string]struct{})
	for host := restrictedPoolFirstHost; host <= restrictedPoolLastHost; host++ {
		online[fmt.Sprintf("10.9.5.%d", host)] = struct{}{}
	}
	fixture.service.onlineIPSource = staticOnlineIPv4Source{addresses: online}

	if _, err := fixture.service.Reserve(
		context.Background(),
		"exhausted-client",
		"request-exhausted",
	); !errors.Is(err, ErrRestrictedIPPoolExhausted) {
		t.Fatalf("pool exhaustion error = %v", err)
	}
}

func TestParseManagementStatusIPv4IsStrict(t *testing.T) {
	addresses, err := parseManagementStatusIPv4([]string{
		"TITLE,OpenVPN 2.6",
		"HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address",
		"CLIENT_LIST,client-a,198.51.100.10:1234,10.9.5.10,,,,,,,,",
		"ROUTING_TABLE,10.9.5.11,client-b,198.51.100.11:1234,0,0",
	})
	if err != nil {
		t.Fatalf("parse management status: %v", err)
	}
	for _, expected := range []string{"10.9.5.10", "10.9.5.11"} {
		if _, exists := addresses[expected]; !exists {
			t.Fatalf("management status missing %s: %v", expected, addresses)
		}
	}

	for _, malformed := range [][]string{
		{"CLIENT_LIST,incomplete"},
		{"ROUTING_TABLE,not-an-ip,client"},
		{""},
	} {
		if _, err := parseManagementStatusIPv4(malformed); err == nil {
			t.Fatalf("expected malformed management status %v to fail", malformed)
		}
	}
}

func TestManagementOnlineIPv4SourceUsesTimeoutAndParsesStatus(t *testing.T) {
	t.Run("valid status", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for management test: %v", err)
		}
		defer listener.Close()
		serverDone := make(chan error, 1)
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverDone <- acceptErr
				return
			}
			defer connection.Close()
			if _, writeErr := connection.Write([]byte(
				">INFO:OpenVPN Management Interface\n",
			)); writeErr != nil {
				serverDone <- writeErr
				return
			}
			command := make([]byte, len("status 2\n"))
			if _, readErr := io.ReadFull(connection, command); readErr != nil {
				serverDone <- readErr
				return
			}
			_, writeErr := connection.Write([]byte(
				"CLIENT_LIST,test-client,198.51.100.1:1234,10.9.5.20,,,,,,,,\n" +
					"END\n",
			))
			serverDone <- writeErr
		}()

		source := managementOnlineIPv4Source{
			network: "tcp",
			address: listener.Addr().String(),
			timeout: time.Second,
		}
		addresses, err := source.OnlineIPv4(context.Background())
		if err != nil {
			t.Fatalf("read management status: %v", err)
		}
		if _, exists := addresses["10.9.5.20"]; !exists {
			t.Fatalf("management addresses = %v", addresses)
		}
		if err := <-serverDone; err != nil {
			t.Fatalf("management test server: %v", err)
		}
	})

	t.Run("read timeout", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for management timeout test: %v", err)
		}
		defer listener.Close()
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer connection.Close()
			_, _ = connection.Write([]byte(
				">INFO:OpenVPN Management Interface\n",
			))
			buffer := make([]byte, len("status 2\n"))
			_, _ = io.ReadFull(connection, buffer)
			_, _ = connection.Read(make([]byte, 1))
		}()

		source := managementOnlineIPv4Source{
			network: "tcp",
			address: listener.Addr().String(),
			timeout: 50 * time.Millisecond,
		}
		if _, err := source.OnlineIPv4(context.Background()); err == nil {
			t.Fatal("expected management read timeout")
		}
		<-serverDone
	})
}

type restrictedIPTestFixture struct {
	root             string
	databasePath     string
	staticClientsDir string
	ippPath          string
	db               *sql.DB
	service          *RestrictedIPAllocationService
}

func newRestrictedIPTestFixture(t *testing.T) *restrictedIPTestFixture {
	t.Helper()
	root := t.TempDir()
	staticClientsDir := filepath.Join(root, "staticclients")
	ippPath := filepath.Join(root, "pki", "ipp.txt")
	if err := os.MkdirAll(staticClientsDir, 0o700); err != nil {
		t.Fatalf("create static clients directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(ippPath), 0o700); err != nil {
		t.Fatalf("create test PKI directory: %v", err)
	}
	writeTestFile(t, ippPath, "")

	databasePath := filepath.Join(root, "db", "data.db")
	if _, err := migrations.Up(context.Background(), databasePath); err != nil {
		t.Fatalf("initialize allocation test database: %v", err)
	}
	db := openRestrictedIPTestDatabase(t, databasePath)
	fixture := &restrictedIPTestFixture{
		root:             root,
		databasePath:     databasePath,
		staticClientsDir: staticClientsDir,
		ippPath:          ippPath,
		db:               db,
	}
	service, err := NewRestrictedIPAllocationService(
		db,
		fixture.config(staticOnlineIPv4Source{addresses: map[string]struct{}{}}),
	)
	if err != nil {
		db.Close()
		t.Fatalf("create allocation service: %v", err)
	}
	service.now = func() time.Time {
		return time.Date(2026, time.July, 27, 12, 0, 0, 0, time.UTC)
	}
	fixture.service = service
	return fixture
}

func (f *restrictedIPTestFixture) config(
	onlineSource OnlineIPv4Source,
) RestrictedIPAllocationConfig {
	return RestrictedIPAllocationConfig{
		StaticClientsDir:   f.staticClientsDir,
		IPPPersistencePath: f.ippPath,
		OnlineIPSource:     onlineSource,
	}
}

func (f *restrictedIPTestFixture) close() {
	if f.db != nil {
		_ = f.db.Close()
	}
}

func openRestrictedIPTestDatabase(t *testing.T, databasePath string) *sql.DB {
	t.Helper()
	dsn := fmt.Sprintf(
		"file:%s?_busy_timeout=5000&_foreign_keys=on&_txlock=immediate",
		databasePath,
	)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		t.Fatalf("open allocation test database: %v", err)
	}
	db.SetMaxOpenConns(8)
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("connect to allocation test database: %v", err)
	}
	return db
}

func insertTestCertificate(
	t *testing.T,
	db *sql.DB,
	id int64,
	commonName string,
	serialNumber string,
	staticIP string,
) {
	t.Helper()
	var staticIPValue any
	if staticIP != "" {
		staticIPValue = staticIP
	}
	if _, err := db.Exec(`INSERT INTO certificates (
		id, common_name, serial_number, status, static_ip
	) VALUES (?, ?, ?, 'valid', ?)`,
		id,
		commonName,
		serialNumber,
		staticIPValue,
	); err != nil {
		t.Fatalf("insert test certificate: %v", err)
	}
}

func writeTestFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create test file directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}
}
