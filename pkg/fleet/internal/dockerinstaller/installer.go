// Package dockerinstaller installs Docker Engine on Linux hosts over SSH.
package dockerinstaller

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"unicode"
)

const (
	statusMarker   = "SEEDFLEET_DOCKER_STATUS="
	versionMarker  = "SEEDFLEET_DOCKER_VERSION="
	maxErrorOutput = 4 << 10
)

//go:embed install.sh
var installScript string

// Status reports whether an installation changed the remote host.
type Status string

const (
	StatusInstalled      Status = "installed"
	StatusAlreadyPresent Status = "already-installed"
)

// Result describes a successful remote installation.
type Result struct {
	Status  Status
	Version string
}

// InvalidTargetError reports a target that cannot safely be passed to SSH.
type InvalidTargetError struct {
	Reason string
}

func (e *InvalidTargetError) Error() string {
	return e.Reason
}

type runner interface {
	Run(context.Context, string, []string, io.Reader) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = stdin
	return command.CombinedOutput()
}

// Installer uses the local OpenSSH client and streams an embedded installer to
// the remote host. SSH authentication and host verification remain under the
// caller's existing SSH configuration.
type Installer struct {
	runner runner
}

// New returns an SSH-based Docker installer.
func New() *Installer {
	return &Installer{runner: commandRunner{}}
}

// Install installs Docker on host, or verifies an existing installation.
func (i *Installer) Install(ctx context.Context, host, user string, port uint16) (Result, error) {
	if err := validateTarget(host, user); err != nil {
		return Result{}, err
	}

	args := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
	}
	if port != 0 {
		args = append(args, "-p", strconv.FormatUint(uint64(port), 10))
	}
	destination := host
	if user != "" {
		destination = user + "@" + host
	}
	args = append(args, "--", destination, "sh", "-s", "--")

	output, err := i.runner.Run(ctx, "ssh", args, strings.NewReader(installScript))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, fmt.Errorf("install Docker on %s: %w", host, ctxErr)
		}
		return Result{}, fmt.Errorf("install Docker on %s: SSH command failed: %w%s", host, err, formatOutput(output))
	}

	result, err := parseResult(output)
	if err != nil {
		return Result{}, fmt.Errorf("install Docker on %s: %w", host, err)
	}
	return result, nil
}

func validateTarget(host, user string) error {
	if host == "" {
		return &InvalidTargetError{Reason: "deployment host is required"}
	}
	if strings.HasPrefix(host, "-") || strings.ContainsRune(host, '@') || containsUnsafeCharacter(host) {
		return &InvalidTargetError{Reason: "deployment host contains unsupported characters"}
	}
	if strings.HasPrefix(user, "-") || strings.ContainsRune(user, '@') || containsUnsafeCharacter(user) {
		return &InvalidTargetError{Reason: "deployment user contains unsupported characters"}
	}
	return nil
}

func containsUnsafeCharacter(value string) bool {
	return strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsSpace(character) || unicode.IsControl(character)
	}) >= 0
}

func parseResult(output []byte) (Result, error) {
	var result Result
	for _, rawLine := range bytes.Split(output, []byte{'\n'}) {
		line := strings.TrimSpace(string(rawLine))
		if value, ok := strings.CutPrefix(line, statusMarker); ok {
			result.Status = Status(value)
		}
		if value, ok := strings.CutPrefix(line, versionMarker); ok {
			result.Version = value
		}
	}
	if result.Status != StatusInstalled && result.Status != StatusAlreadyPresent {
		return Result{}, fmt.Errorf("remote installer returned an unknown status %q", result.Status)
	}
	if result.Version == "" {
		return Result{}, fmt.Errorf("remote installer did not report the Docker version")
	}
	return result, nil
}

func formatOutput(output []byte) string {
	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return ""
	}
	if len(trimmed) > maxErrorOutput {
		trimmed = append(append([]byte(nil), trimmed[:maxErrorOutput]...), []byte("...")...)
	}
	return ": " + string(trimmed)
}
