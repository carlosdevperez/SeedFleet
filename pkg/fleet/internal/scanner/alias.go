package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// DeviceAlias is a user-controlled identity for a stable MAC address. Aliases
// fill gaps left by devices that advertise names only intermittently.
type DeviceAlias struct {
	Name         string `json:"name"`
	Hostname     string `json:"hostname,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
}

func normalizeMAC(mac string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(mac)))
}

func normalizeAliases(aliases map[string]DeviceAlias) map[string]DeviceAlias {
	result := make(map[string]DeviceAlias, len(aliases))
	for mac, alias := range aliases {
		alias.Name = strings.TrimSpace(alias.Name)
		alias.Hostname = strings.TrimSuffix(strings.TrimSpace(alias.Hostname), ".")
		alias.Manufacturer = strings.TrimSpace(alias.Manufacturer)
		result[normalizeMAC(mac)] = alias
	}
	return result
}

func aliasForMAC(aliases map[string]DeviceAlias, mac string) (DeviceAlias, bool) {
	alias, ok := aliases[normalizeMAC(mac)]
	return alias, ok && (alias.Name != "" || alias.Hostname != "" || alias.Manufacturer != "")
}

// LoadAliases reads optional user-controlled identities for the scanner. A
// missing path is treated as an empty configuration.
func LoadAliases(path string) (map[string]DeviceAlias, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	aliases := make(map[string]DeviceAlias)
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&aliases); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("alias file contains more than one JSON value")
		}
		return nil, err
	}
	return aliases, nil
}
