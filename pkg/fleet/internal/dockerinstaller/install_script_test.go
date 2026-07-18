//go:build linux

package dockerinstaller

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScriptRecognizesExistingDocker(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "uname", "#!/bin/sh\nprintf 'Linux\\n'\n")
	writeExecutable(t, bin, "docker", `#!/bin/sh
case "$1" in
	info) exit 0 ;;
	--version) printf 'Docker version 28.0.1, build test\n' ;;
	*) exit 1 ;;
esac
`)

	output, err := runInstallScript(t, bin, nil)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, output)
	}
	result, err := parseResult(output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusAlreadyPresent || result.Version != "Docker version 28.0.1, build test" {
		t.Fatalf("result = %#v", result)
	}
}

func TestInstallScriptInstallsAndVerifiesDocker(t *testing.T) {
	bin := t.TempDir()
	installerPath := filepath.Join(bin, "downloaded-installer.sh")
	dockerPath := filepath.Join(bin, "docker")
	writeExecutable(t, bin, "uname", "#!/bin/sh\nprintf 'Linux\\n'\n")
	writeExecutable(t, bin, "id", "#!/bin/sh\nprintf '0\\n'\n")
	writeExecutable(t, bin, "mktemp", "#!/bin/sh\nprintf '%s\\n' \"$SEEDFLEET_TEST_INSTALLER\"\n")
	writeExecutable(t, bin, "curl", `#!/bin/sh
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-o" ]; then
		shift
		printf '#!/bin/sh\nexit 0\n' > "$1"
	fi
	shift
done
/bin/chmod +x "$SEEDFLEET_TEST_DOCKER"
`)
	writeFile(t, dockerPath, `#!/bin/sh
case "$1" in
	info) exit 0 ;;
	--version) printf 'Docker version 28.0.1, build test\n' ;;
	*) exit 1 ;;
esac
`, 0o644)
	for name, target := range map[string]string{
		"env": "/usr/bin/env",
		"rm":  "/bin/rm",
		"sh":  "/bin/sh",
	} {
		if err := os.Symlink(target, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}

	output, err := runInstallScript(t, bin, []string{
		"SEEDFLEET_TEST_INSTALLER=" + installerPath,
		"SEEDFLEET_TEST_DOCKER=" + dockerPath,
	})
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, output)
	}
	result, err := parseResult(output)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusInstalled || result.Version != "Docker version 28.0.1, build test" {
		t.Fatalf("result = %#v", result)
	}
}

func TestInstallScriptRejectsNonLinuxHost(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, bin, "uname", "#!/bin/sh\nprintf 'FreeBSD\\n'\n")

	output, err := runInstallScript(t, bin, nil)
	if err == nil || !strings.Contains(string(output), "supported only on Linux") {
		t.Fatalf("error = %v; output = %s", err, output)
	}
}

func runInstallScript(t *testing.T, path string, extraEnvironment []string) ([]byte, error) {
	t.Helper()
	command := exec.CommandContext(context.Background(), "/bin/sh", "-s")
	command.Stdin = strings.NewReader(installScript)
	command.Env = append(os.Environ(), append([]string{"PATH=" + path}, extraEnvironment...)...)
	return command.CombinedOutput()
}

func writeExecutable(t *testing.T, directory, name, content string) {
	t.Helper()
	writeFile(t, filepath.Join(directory, name), content, 0o755)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
