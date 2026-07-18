#!/bin/sh

set -eu

if [ "$(uname -s)" != "Linux" ]; then
	echo "Docker Engine installation is supported only on Linux hosts" >&2
	exit 1
fi

seedfleet_status=already-installed

seedfleet_privileged() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	elif command -v sudo >/dev/null 2>&1; then
		sudo -n "$@"
	else
		return 127
	fi
}

if ! command -v docker >/dev/null 2>&1; then
	seedfleet_status=installed

	if [ "$(id -u)" -ne 0 ]; then
		if ! command -v sudo >/dev/null 2>&1 || ! sudo -n true >/dev/null 2>&1; then
			echo "Docker installation requires root or non-interactive sudo access" >&2
			exit 1
		fi
	fi

	seedfleet_tmp=$(mktemp "${TMPDIR:-/tmp}/seedfleet-docker.XXXXXX")
	trap 'rm -f "$seedfleet_tmp"' EXIT HUP INT TERM

	if command -v curl >/dev/null 2>&1; then
		curl -fsSL https://get.docker.com -o "$seedfleet_tmp"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO "$seedfleet_tmp" https://get.docker.com
	else
		echo "Docker installation requires curl or wget" >&2
		exit 1
	fi

	seedfleet_privileged env VERSION= sh "$seedfleet_tmp"
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "Docker installer completed but the docker command is unavailable" >&2
	exit 1
fi

# The convenience installer does not start Docker automatically on every
# supported distribution. Start it when neither the current user nor root can
# reach the daemon, then verify that the engine is operational.
if ! docker info >/dev/null 2>&1 && ! seedfleet_privileged docker info >/dev/null 2>&1; then
	if command -v systemctl >/dev/null 2>&1 && seedfleet_privileged systemctl enable --now docker; then
		:
	elif command -v service >/dev/null 2>&1 && seedfleet_privileged service docker start; then
		:
	else
		echo "Docker is installed but its daemon is not running" >&2
		exit 1
	fi
fi

if ! docker info >/dev/null 2>&1 && ! seedfleet_privileged docker info >/dev/null 2>&1; then
	echo "Docker is installed but its daemon could not be reached" >&2
	exit 1
fi

seedfleet_version=$(docker --version)
printf '\nSEEDFLEET_DOCKER_STATUS=%s\n' "$seedfleet_status"
printf 'SEEDFLEET_DOCKER_VERSION=%s\n' "$seedfleet_version"
