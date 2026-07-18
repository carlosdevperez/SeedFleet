package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
	_ "modernc.org/sqlite"
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS devices (
	id TEXT PRIMARY KEY,
	ip TEXT NOT NULL UNIQUE,
	mac TEXT NOT NULL,
	mac_key TEXT NOT NULL,
	name TEXT NOT NULL,
	manufacturer TEXT NOT NULL,
	hostname TEXT NOT NULL,
	open_ports TEXT NOT NULL,
	open_udp_ports TEXT NOT NULL DEFAULT '[]',
	discovered_by TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS devices_mac_key
	ON devices(mac_key) WHERE mac_key <> '';
`

const deviceColumns = `id, ip, mac, name, manufacturer, hostname,
	open_ports, open_udp_ports, discovered_by, first_seen, last_seen`

// SQLite is a persistent device inventory backed by SQLite.
type SQLite struct {
	db *sql.DB
}

// NewSQLite opens path and creates the inventory schema when necessary.
func NewSQLite(path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("SQLite inventory path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite inventory: %w", err)
	}
	// A single connection also makes :memory: databases behave consistently.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure SQLite inventory: %w", err)
	}
	if _, err := db.Exec(sqliteSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize SQLite inventory: %w", err)
	}
	if err := ensureSQLiteUDPPortsColumn(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate SQLite inventory: %w", err)
	}
	return &SQLite{db: db}, nil
}

func ensureSQLiteUDPPortsColumn(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(devices)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var (
			position     int
			name         string
			columnType   string
			notNull      int
			defaultValue any
			primaryKey   int
		)
		if err := rows.Scan(&position, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "open_udp_ports" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE devices ADD COLUMN open_udp_ports TEXT NOT NULL DEFAULT '[]'`)
	return err
}

// Save commits a scan result in one transaction and returns devices in input
// order.
func (s *SQLite) Save(ctx context.Context, found []devices.Device) ([]devices.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateDevices(found); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin SQLite inventory update: %w", err)
	}
	defer tx.Rollback()

	result := make([]devices.Device, len(found))
	for index, item := range found {
		stored, err := saveSQLiteDevice(ctx, tx, item)
		if err != nil {
			return nil, err
		}
		result[index] = stored
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit SQLite inventory update: %w", err)
	}
	return result, nil
}

func saveSQLiteDevice(ctx context.Context, tx *sql.Tx, found devices.Device) (devices.Device, error) {
	existing, ok, err := findSQLiteDevice(ctx, tx, found)
	if err != nil {
		return devices.Device{}, err
	}
	if ok {
		found = devices.Refresh(existing, found)
	} else if found.ID == "" {
		found.ID, err = newDeviceID()
		if err != nil {
			return devices.Device{}, fmt.Errorf("create device identity: %w", err)
		}
	}

	// The current observation owns its IP and MAC. Remove stale records that
	// would otherwise conflict with this durable device.
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE ip = ? AND id <> ?`, found.IP.String(), found.ID); err != nil {
		return devices.Device{}, fmt.Errorf("remove stale SQLite address: %w", err)
	}
	key := macKey(found.MAC)
	if key != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE mac_key = ? AND id <> ?`, key, found.ID); err != nil {
			return devices.Device{}, fmt.Errorf("remove stale SQLite identity: %w", err)
		}
	}

	ports, err := json.Marshal(found.OpenPorts)
	if err != nil {
		return devices.Device{}, fmt.Errorf("encode device ports: %w", err)
	}
	udpPorts, err := json.Marshal(found.OpenUDPPorts)
	if err != nil {
		return devices.Device{}, fmt.Errorf("encode device UDP ports: %w", err)
	}
	methods, err := json.Marshal(found.DiscoveredBy)
	if err != nil {
		return devices.Device{}, fmt.Errorf("encode device discovery methods: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO devices (
			id, ip, mac, mac_key, name, manufacturer, hostname,
			open_ports, open_udp_ports, discovered_by, first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			ip = excluded.ip,
			mac = excluded.mac,
			mac_key = excluded.mac_key,
			name = excluded.name,
			manufacturer = excluded.manufacturer,
			hostname = excluded.hostname,
			open_ports = excluded.open_ports,
			open_udp_ports = excluded.open_udp_ports,
			discovered_by = excluded.discovered_by,
			first_seen = excluded.first_seen,
			last_seen = excluded.last_seen
	`,
		found.ID, found.IP.String(), found.MAC, key, found.Name,
		found.Manufacturer, found.Hostname, string(ports), string(udpPorts), string(methods),
		formatTime(found.FirstSeen), formatTime(found.LastSeen),
	)
	if err != nil {
		return devices.Device{}, fmt.Errorf("save device in SQLite inventory: %w", err)
	}
	return clone(found), nil
}

func findSQLiteDevice(ctx context.Context, tx *sql.Tx, found devices.Device) (devices.Device, bool, error) {
	if found.ID != "" {
		item, ok, err := querySQLiteDevice(ctx, tx, "id = ?", found.ID)
		if err != nil || ok {
			return item, ok, err
		}
	}
	key := macKey(found.MAC)
	if key != "" {
		item, ok, err := querySQLiteDevice(ctx, tx, "mac_key = ?", key)
		if err != nil || ok {
			return item, ok, err
		}
	}
	item, ok, err := querySQLiteDevice(ctx, tx, "ip = ?", found.IP.String())
	if err != nil || !ok {
		return item, ok, err
	}
	existingKey := macKey(item.MAC)
	if key != "" && existingKey != "" && key != existingKey {
		return devices.Device{}, false, nil
	}
	return item, true, nil
}

func querySQLiteDevice(ctx context.Context, tx *sql.Tx, predicate string, argument any) (devices.Device, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE `+predicate, argument)
	item, err := scanSQLiteDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return devices.Device{}, false, nil
	}
	if err != nil {
		return devices.Device{}, false, fmt.Errorf("query SQLite inventory: %w", err)
	}
	return item, true, nil
}

// List returns all devices sorted by IP address.
func (s *SQLite) List(ctx context.Context) ([]devices.Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+deviceColumns+` FROM devices`)
	if err != nil {
		return nil, fmt.Errorf("list SQLite inventory: %w", err)
	}
	defer rows.Close()

	result := make([]devices.Device, 0)
	for rows.Next() {
		item, err := scanSQLiteDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("read SQLite inventory: %w", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate SQLite inventory: %w", err)
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].IP.Compare(result[right].IP) < 0
	})
	return result, nil
}

type sqliteScanner interface {
	Scan(...any) error
}

func scanSQLiteDevice(row sqliteScanner) (devices.Device, error) {
	var (
		item      devices.Device
		address   string
		ports     string
		udpPorts  string
		methods   string
		firstSeen string
		lastSeen  string
	)
	if err := row.Scan(
		&item.ID, &address, &item.MAC, &item.Name, &item.Manufacturer,
		&item.Hostname, &ports, &udpPorts, &methods, &firstSeen, &lastSeen,
	); err != nil {
		return devices.Device{}, err
	}
	var err error
	item.IP, err = netip.ParseAddr(address)
	if err != nil {
		return devices.Device{}, fmt.Errorf("parse stored IP address %q: %w", address, err)
	}
	if err := json.Unmarshal([]byte(ports), &item.OpenPorts); err != nil {
		return devices.Device{}, fmt.Errorf("decode stored ports: %w", err)
	}
	if err := json.Unmarshal([]byte(udpPorts), &item.OpenUDPPorts); err != nil {
		return devices.Device{}, fmt.Errorf("decode stored UDP ports: %w", err)
	}
	if err := json.Unmarshal([]byte(methods), &item.DiscoveredBy); err != nil {
		return devices.Device{}, fmt.Errorf("decode stored discovery methods: %w", err)
	}
	item.FirstSeen, err = time.Parse(time.RFC3339Nano, firstSeen)
	if err != nil {
		return devices.Device{}, fmt.Errorf("parse stored first-seen time: %w", err)
	}
	item.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeen)
	if err != nil {
		return devices.Device{}, fmt.Errorf("parse stored last-seen time: %w", err)
	}
	return item, nil
}

func formatTime(value time.Time) string {
	return value.Format(time.RFC3339Nano)
}

// Close closes the underlying database.
func (s *SQLite) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close SQLite inventory: %w", err)
	}
	return nil
}
