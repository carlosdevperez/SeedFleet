package dockerinstaller

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	name   string
	args   []string
	stdin  string
	output []byte
	err    error
}

func (r *fakeRunner) Run(_ context.Context, name string, args []string, stdin io.Reader) ([]byte, error) {
	r.name = name
	r.args = append([]string(nil), args...)
	content, err := io.ReadAll(stdin)
	if err != nil {
		return nil, err
	}
	r.stdin = string(content)
	return r.output, r.err
}

func TestInstallRunsEmbeddedScriptOverSSH(t *testing.T) {
	runner := &fakeRunner{output: []byte("installer output\nSEEDFLEET_DOCKER_STATUS=installed\nSEEDFLEET_DOCKER_VERSION=Docker version 28.0.1\n")}
	installer := &Installer{runner: runner}

	result, err := installer.Install(context.Background(), "node-1.local", "operator", 2222)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-p", "2222",
		"--", "operator@node-1.local", "sh", "-s", "--",
	}
	if runner.name != "ssh" || !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("command = %q %q", runner.name, runner.args)
	}
	if !strings.Contains(runner.stdin, "https://get.docker.com") || !strings.Contains(runner.stdin, "sudo -n") {
		t.Fatalf("embedded installer is missing expected behavior:\n%s", runner.stdin)
	}
	if result.Status != StatusInstalled || result.Version != "Docker version 28.0.1" {
		t.Fatalf("result = %#v", result)
	}
}

func TestInstallUsesSSHConfigurationDefaults(t *testing.T) {
	runner := &fakeRunner{output: []byte("SEEDFLEET_DOCKER_STATUS=already-installed\nSEEDFLEET_DOCKER_VERSION=Docker version 27.5.0\n")}
	installer := &Installer{runner: runner}

	result, err := installer.Install(context.Background(), "192.0.2.10", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	wantArgs := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"--", "192.0.2.10", "sh", "-s", "--",
	}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("args = %q, want %q", runner.args, wantArgs)
	}
	if result.Status != StatusAlreadyPresent {
		t.Fatalf("status = %q", result.Status)
	}
}

func TestInstallRejectsUnsafeTargets(t *testing.T) {
	tests := []struct {
		name string
		host string
		user string
	}{
		{name: "missing host"},
		{name: "host option", host: "-oProxyCommand=bad"},
		{name: "host whitespace", host: "node one"},
		{name: "host user separator", host: "root@node"},
		{name: "user option", host: "node", user: "-Fbad"},
		{name: "user whitespace", host: "node", user: "root user"},
		{name: "user separator", host: "node", user: "root@other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakeRunner{}
			_, err := (&Installer{runner: runner}).Install(context.Background(), test.host, test.user, 0)
			var invalid *InvalidTargetError
			if !errors.As(err, &invalid) {
				t.Fatalf("error = %T %v", err, err)
			}
			if runner.name != "" {
				t.Fatalf("runner called with %q", runner.name)
			}
		})
	}
}

func TestInstallReportsSSHFailure(t *testing.T) {
	runner := &fakeRunner{output: []byte("permission denied"), err: errors.New("exit status 255")}
	_, err := (&Installer{runner: runner}).Install(context.Background(), "node", "", 0)
	if err == nil || !strings.Contains(err.Error(), "exit status 255") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %v", err)
	}
}

func TestInstallRequiresResultMarkers(t *testing.T) {
	runner := &fakeRunner{output: []byte("installation unexpectedly stopped")}
	_, err := (&Installer{runner: runner}).Install(context.Background(), "node", "", 0)
	if err == nil || !strings.Contains(err.Error(), "unknown status") {
		t.Fatalf("error = %v", err)
	}
}
