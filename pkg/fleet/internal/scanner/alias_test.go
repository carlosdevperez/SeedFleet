package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAliasForMACNormalizesSeparators(t *testing.T) {
	aliases := normalizeAliases(map[string]DeviceAlias{
		"4A-91-A3-58-50-08": {Name: " Phone ", Hostname: "phone.local."},
	})
	alias, ok := aliasForMAC(aliases, "4a:91:a3:58:50:08")
	if !ok || alias.Name != "Phone" || alias.Hostname != "phone.local" {
		t.Fatalf("alias = %#v, ok = %v", alias, ok)
	}
}

func TestLoadAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aliases.json")
	if err := os.WriteFile(path, []byte(`{"aa:bb:cc:dd:ee:ff":{"name":"Printer"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	aliases, err := LoadAliases(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := aliases["aa:bb:cc:dd:ee:ff"].Name; got != "Printer" {
		t.Fatalf("alias name = %q", got)
	}
}

func TestLoadAliasesAllowsMissingOptionalFile(t *testing.T) {
	aliases, err := LoadAliases(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || aliases != nil {
		t.Fatalf("aliases = %#v, err = %v", aliases, err)
	}
}
