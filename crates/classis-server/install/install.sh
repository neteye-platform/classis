#!/bin/sh
# Enrols this host from the Server that served this script.
#
# The same install the `.deb` and the `.rpm` do, from a URL: the Server hands out the Client archive
# it already hands a fleet self-update, and the install itself is the Client's own
# `service install`, never a second one. The system account, the registration and the `PATH`
# symlink are laid exactly as `packaging/linux/postinst` lays them, so a host installed from a URL
# and one installed from a package end up identical — including the two default roots, since no
# `--root` is passed here either.
#
# TLS was settled before this ran: the host fetched this file over it. So nothing here terminates
# TLS, provisions a CA, or relaxes a check — `curl` verifies the Server against the trust the host
# already has, at TLS 1.3, and follows no redirect.
#
# The enrolment key is an argument to `enrol` and never part of a URL, so it cannot reach a proxy's
# or the Server's access log. It does appear in that command's arguments, exactly as it does for
# the operator who types `classis enrol` by hand.
#
# Usage: sh install.sh --url <base-url> --key <enrolment-key>
#
# Every function is defined before anything runs and `main` is called last: this file arrives
# through a pipe, and a shell reading a pipe parses and runs one command at a time, so a truncated
# download must be unable to have done anything yet.
set -eu
umask 077

url=''
key=''
base=''
endpoint=''
scheme=''
arch=''
tmp=''
archive=''

die() {
	printf 'classis install: %s\n' "$1" >&2
	exit 1
}

usage() {
	printf 'usage: install.sh --url <base-url> --key <enrolment-key>\n' >&2
}

# Whether $1 holds only characters in the set $2 — so no whitespace, no control character, and
# nothing a shell or a URL would read as structure rather than as text.
only() {
	case "$(printf '%s' "$1" | tr -d "$2")" in
	'') return 0 ;;
	*) return 1 ;;
	esac
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--url)
			[ "$#" -ge 2 ] || die '--url needs a value'
			url=$2
			shift 2
			;;
		--key)
			[ "$#" -ge 2 ] || die '--key needs a value'
			key=$2
			shift 2
			;;
		-h | --help)
			usage
			exit 0
			;;
		*)
			die "unknown argument: $1"
			;;
		esac
	done
	[ -n "$url" ] || {
		usage
		die '--url is required'
	}
	[ -n "$key" ] || {
		usage
		die '--key is required'
	}
}

check_args() {
	case "$url" in
	https://*) scheme=https ;;
	http://*) scheme=http ;;
	*) die "$url must start with https://" ;;
	esac
	# The rule `enrol` applies to its own base URL (`enrolment::route`): a scheme, a host and
	# perhaps a path, with no credentials, query or fragment.
	only "$url" 'A-Za-z0-9:/._~%[]-' || die "$url holds a character a URL may not hold"
	case "$url" in
	*'?'* | *'#'* | *'@'* | *'..'*) die "$url must be a scheme, a host and perhaps a path" ;;
	esac
	authority=${url#*://}
	authority=${authority%%/*}
	case "$authority" in
	'[::1]'*) host='[::1]' ;;
	*) host=${authority%%:*} ;;
	esac
	# A name never counts as loopback, `localhost` included, because a name can be made to resolve
	# anywhere. Same rule as `opamp::endpoint::is_loopback_literal`.
	if [ "$scheme" = http ] && [ "$host" != 127.0.0.1 ] && [ "$host" != '[::1]' ]; then
		die "$url: plaintext is for 127.0.0.1 and ::1 alone — use https://"
	fi
	# The key's own alphabet: `cle1_<space>_<secret>`, letters, digits, `-` and `_`
	# (`classis_core::enrolment_key`). Not starting with a dash is what keeps it an argument and
	# never a flag of `enrol`.
	only "$key" 'A-Za-z0-9_-' || die 'the enrolment key holds a character a key may not hold'
	case "$key" in
	-*) die 'the enrolment key must not start with a dash' ;;
	esac
	base=$url
	while [ "${base%/}" != "$base" ]; do
		base=${base%/}
	done
	if [ "$scheme" = https ]; then
		endpoint="wss://${base#https://}/v1/opamp"
	else
		endpoint="ws://${base#http://}/v1/opamp"
	fi
}

require_tools() {
	for tool in curl tar tr mktemp uname id getent useradd ln chmod; do
		command -v "$tool" >/dev/null 2>&1 || die "this host has no $tool"
	done
}

pick_arch() {
	machine=$(uname -m)
	case "$machine" in
	x86_64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "no Client build for $machine" ;;
	esac
}

# curl is never asked to follow a redirect, and it answers one with exit status 0 — which is why the
# caller checks the status code rather than trusting the download to have failed.
fetch() {
	if [ "$scheme" = https ]; then
		curl -fsS --proto '=https' --tlsv1.3 --output "$2" --write-out '%{http_code}' "$1"
	else
		curl -fsS --proto '=http' --output "$2" --write-out '%{http_code}' "$1"
	fi
}

download() {
	code=$(fetch "$base/v1/install/linux/$arch" "$archive") ||
		die "cannot download $base/v1/install/linux/$arch"
	[ "$code" = 200 ] || die "$base/v1/install/linux/$arch answered $code"
}

# Only the one member the release workflow packs, and never a path the archive chose: an archive
# that holds anything else is refused before a byte of it is written.
unpack() {
	members=$(tar -tzf "$archive") || die "$archive is not a .tar.gz"
	[ "$members" = supervisor ] || die 'the archive holds something other than the Client'
	tar -xzf "$archive" -C "$tmp" -- supervisor
	chmod 700 "$tmp/supervisor"
}

# Verbatim from `packaging/linux/postinst`, so the account one install path creates is the account
# the other creates: a system account, no password, no login shell, its home the data root.
create_account() {
	if ! getent passwd classis >/dev/null 2>&1; then
		if getent group classis >/dev/null 2>&1; then
			useradd --system --gid classis --no-create-home --home-dir /var/lib/classis \
				--shell /usr/sbin/nologin classis
		else
			useradd --system --user-group --no-create-home --home-dir /var/lib/classis \
				--shell /usr/sbin/nologin classis
		fi
	fi
}

main() {
	parse_args "$@"
	check_args
	[ "$(id -u)" = 0 ] || die 'this must run as root'
	require_tools
	pick_arch
	# Re-registration is `classis service install` and `classis enrol`, not a second delivery of
	# the program: refusing here is what keeps this script from swinging the `current` pointer of a
	# host an operator already manages.
	if [ -e /etc/systemd/system/classis.service ]; then
		die 'this host is registered already — run classis enrol, or remove the service first'
	fi
	tmp=$(mktemp -d) || die 'cannot make a private temporary directory'
	trap 'rm -rf -- "$tmp"' EXIT INT TERM
	archive=$tmp/client.tar.gz
	download
	unpack
	create_account
	# A first registration every time, since an existing unit was refused above — so the account is
	# named, as the post-install names it in that same case.
	"$tmp/supervisor" service install --endpoint "$endpoint" --run-as classis
	# `-n`: without it, ln would place the link *inside* the directory an existing link resolves to.
	ln -sfn /opt/classis/current/supervisor /usr/bin/classis
	"$tmp/supervisor" enrol "$base" "$key"
	printf '%s\n' 'Installed and enrolled: the service runs and starts at boot.'
}

main "$@"
