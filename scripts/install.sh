#!/bin/sh
# ServerOk bootstrap installer.
#
#   bash <(curl -sL https://raw.githubusercontent.com/Zagorsky17/ServerOk/main/scripts/install.sh)
#   curl -sL https://raw.githubusercontent.com/Zagorsky17/ServerOk/main/scripts/install.sh | bash -s -- -all
#
# It downloads the release binary for this platform, verifies its SHA-256 and
# runs it. Arguments after `--` are passed straight to serverok.
set -eu

REPO="${SERVERTESTER_REPO:-Zagorsky17/ServerOk}"
BINARY="serverok"
INSTALL_DIR=""
NO_VERIFY=0

red()   { printf '\033[31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
info()  { printf '\033[36m%s\033[0m\n' "$*"; }

die() { red "error: $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1; }

# --install [dir] keeps the binary instead of running it from a temp dir.
# Script options are consumed here; every other argument is rotated to the end
# of the positional parameters. Collecting them in a string and re-splitting it
# would break exactly the arguments worth forwarding: -disk-path with a space
# in it, or anything containing a glob character.
argc=$#
while [ "$argc" -gt 0 ]; do
	arg="$1"; shift
	argc=$((argc - 1))
	case "$arg" in
		--install) INSTALL_DIR="/usr/local/bin" ;;
		--install=*) INSTALL_DIR="${arg#--install=}" ;;
		--no-verify) NO_VERIFY=1 ;;
		*) set -- "$@" "$arg" ;;
	esac
done

detect_platform() {
	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	arch=$(uname -m)
	case "$os" in
		linux|darwin|freebsd) ;;
		*) die "unsupported OS: $os" ;;
	esac
	case "$arch" in
		x86_64|amd64)   arch=amd64 ;;
		aarch64|arm64)  arch=arm64 ;;
		i386|i686)      arch=386 ;;
		armv7l|armv6l)  arch=arm ;;
		*) die "unsupported architecture: $arch" ;;
	esac
	printf '%s_%s' "$os" "$arch"
}

fetch() {
	url="$1"; out="$2"
	if need curl; then
		curl -fsSL --retry 3 "$url" -o "$out"
	elif need wget; then
		wget -qO "$out" "$url"
	else
		die "neither curl nor wget is available"
	fi
}

fetch_stdout() {
	if need curl; then
		curl -fsSL --retry 3 "$1"
	elif need wget; then
		wget -qO- "$1"
	else
		die "neither curl nor wget is available"
	fi
}

latest_tag() {
	fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" \
		| grep -m1 '"tag_name"' \
		| sed 's/.*"tag_name" *: *"\([^"]*\)".*/\1/'
}

# verify_checksum fails closed: a download that cannot be verified is not
# installed unless the caller explicitly passed --no-verify.
verify_checksum() {
	file="$1"; sums="$2"; name="$3"
	expected=$(awk -v n="$name" '$2 == n || $2 == "*" n { print $1; exit }' "$sums")
	if [ -z "$expected" ]; then
		[ "$NO_VERIFY" -eq 1 ] || die "no checksum entry for $name (pass --no-verify to install anyway)"
		info "no checksum entry for $name, continuing because --no-verify was given"
		return 0
	fi
	if need sha256sum; then
		actual=$(sha256sum "$file" | awk '{print $1}')
	elif need shasum; then
		actual=$(shasum -a 256 "$file" | awk '{print $1}')
	else
		[ "$NO_VERIFY" -eq 1 ] || die "no sha256 tool available to verify the download (install coreutils, or pass --no-verify)"
		info "no sha256 tool found, continuing because --no-verify was given"
		return 0
	fi
	[ "$expected" = "$actual" ] || die "checksum mismatch for $name"
	green "checksum verified"
}

PLATFORM=$(detect_platform)
info "platform: $PLATFORM"

if [ -n "${SERVERTESTER_BASE_URL:-}" ]; then
	TAG="${SERVERTESTER_VERSION:-local}"
else
	TAG="${SERVERTESTER_VERSION:-$(latest_tag || true)}"
	[ -n "$TAG" ] || die "cannot determine the latest release of $REPO (set SERVERTESTER_VERSION=vX.Y.Z to pin one)"
fi
info "version:  $TAG"

TMPDIR_ST=$(mktemp -d 2>/dev/null || mktemp -d -t serverok)
cleanup() { rm -rf "$TMPDIR_ST"; }
trap cleanup EXIT INT TERM

ARCHIVE="${BINARY}_${PLATFORM}.tar.gz"
# SERVERTESTER_BASE_URL points the download at a mirror or a local directory
# server; it must contain the same file names as a GitHub release.
BASE="${SERVERTESTER_BASE_URL:-https://github.com/$REPO/releases/download/$TAG}"

info "downloading $ARCHIVE"
if ! fetch "$BASE/$ARCHIVE" "$TMPDIR_ST/$ARCHIVE"; then
	red "cannot download $BASE/$ARCHIVE"
	die "release $TAG has no $ARCHIVE (yet) — wait for the release to finish publishing, or pin a known one with SERVERTESTER_VERSION=vX.Y.Z"
fi
if fetch "$BASE/checksums.txt" "$TMPDIR_ST/checksums.txt" 2>/dev/null; then
	verify_checksum "$TMPDIR_ST/$ARCHIVE" "$TMPDIR_ST/checksums.txt" "$ARCHIVE"
fi

tar -xzf "$TMPDIR_ST/$ARCHIVE" -C "$TMPDIR_ST"
chmod +x "$TMPDIR_ST/$BINARY"

if [ -n "$INSTALL_DIR" ]; then
	[ -d "$INSTALL_DIR" ] || mkdir -p "$INSTALL_DIR" 2>/dev/null || true
	if [ -w "$INSTALL_DIR" ]; then
		mv "$TMPDIR_ST/$BINARY" "$INSTALL_DIR/$BINARY"
	elif need sudo; then
		sudo mv "$TMPDIR_ST/$BINARY" "$INSTALL_DIR/$BINARY"
	else
		die "cannot write to $INSTALL_DIR (run as root or pass --install=<dir>)"
	fi
	green "installed to $INSTALL_DIR/$BINARY"
	exit 0
fi

# When this script itself is piped into a shell, stdin is the pipe rather than
# the terminal — reconnect it so the interactive menu still works.
status=0
# `[ -r /dev/tty ]` is not enough: the device node can exist while opening it
# fails (containers, cron), so try an actual open.
if [ -t 0 ]; then
	"$TMPDIR_ST/$BINARY" "$@" || status=$?
elif (exec 3</dev/tty) 2>/dev/null; then
	"$TMPDIR_ST/$BINARY" "$@" < /dev/tty || status=$?
else
	# No terminal at all (cron, CI): run everything non-interactively.
	"$TMPDIR_ST/$BINARY" -all "$@" || status=$?
fi
exit "$status"
