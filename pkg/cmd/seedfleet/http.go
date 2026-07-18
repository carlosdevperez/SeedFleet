package seedfleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"time"

	"github.com/carlosdevperez/seedfleet/pkg/fleet"
	"github.com/carlosdevperez/seedfleet/pkg/fleet/devices"
)

const maximumRequestBody = 1 << 20

type provider interface {
	Scan(context.Context, string) (fleet.ScanResult, error)
	List(context.Context) ([]devices.Device, error)
}

type api struct {
	provider provider
}

func newHandler(provider provider) http.Handler {
	api := &api{provider: provider}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", api.health)
	mux.HandleFunc("GET /devices", api.listDevices)
	mux.HandleFunc("POST /scans", api.scan)
	return mux
}

func (a *api) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func (a *api) listDevices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	items, err := a.provider.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Message: "inventory lookup failed"})
		return
	}
	writeJSON(w, http.StatusOK, deviceCollectionFrom("", items))
}

func (a *api) scan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := requireJSON(r); err != nil {
		writeJSON(w, err.Status, errorResponse{Message: err.Message})
		return
	}
	var request scanRequest
	if err := decodeJSON(w, r, &request); err != nil || request.Network == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Message: "body must be JSON containing a non-empty network CIDR"})
		return
	}
	result, err := a.provider.Scan(r.Context(), request.Network)
	if err != nil {
		if errors.Is(err, fleet.ErrScanInProgress) {
			writeJSON(w, http.StatusConflict, errorResponse{Message: err.Error()})
			return
		}
		var invalid *fleet.InvalidNetworkError
		if errors.As(err, &invalid) {
			writeJSON(w, http.StatusBadRequest, errorResponse{Message: invalid.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse{Message: "scan failed"})
		return
	}
	writeJSON(w, http.StatusOK, deviceCollectionFrom(result.Network, result.Devices))
}

type scanRequest struct {
	Network string `json:"network"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type errorResponse struct {
	Message string `json:"error"`
}

type deviceCollection struct {
	Network string           `json:"network,omitempty"`
	Count   int              `json:"count"`
	Devices []deviceResponse `json:"devices"`
}

type deviceResponse struct {
	IP           netip.Addr `json:"ip"`
	MAC          string     `json:"mac,omitempty"`
	Name         string     `json:"name,omitempty"`
	Manufacturer string     `json:"manufacturer,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	OpenPorts    []uint16   `json:"openPorts"`
	DiscoveredBy []string   `json:"discoveredBy"`
	FirstSeen    time.Time  `json:"firstSeen"`
	LastSeen     time.Time  `json:"lastSeen"`
}

func deviceCollectionFrom(network string, items []devices.Device) deviceCollection {
	result := make([]deviceResponse, len(items))
	for index, item := range items {
		result[index] = deviceResponse{
			IP:           item.IP,
			MAC:          item.MAC,
			Name:         item.Name,
			Manufacturer: item.Manufacturer,
			Hostname:     item.Hostname,
			OpenPorts:    append([]uint16{}, item.OpenPorts...),
			DiscoveredBy: append([]string{}, item.DiscoveredBy...),
			FirstSeen:    item.FirstSeen,
			LastSeen:     item.LastSeen,
		}
	}
	return deviceCollection{Network: network, Count: len(result), Devices: result}
}

type requestError struct {
	Status  int
	Message string
}

func requireJSON(r *http.Request) *requestError {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return &requestError{Status: http.StatusBadRequest, Message: "Content-Type is required"}
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return &requestError{Status: http.StatusBadRequest, Message: "Content-Type is invalid"}
	}
	if mediaType != "application/json" {
		return &requestError{Status: http.StatusUnsupportedMediaType, Message: "only application/json content is supported"}
	}
	return nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maximumRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
