#!/usr/bin/env bash
# kiro-classification: public
#
# Denies every outbound packet except loopback and the GitHub Actions runner's
# communication endpoints, then proves the denial holds.
#
# The offline suite runs with no deployed AWS resources and no network access (R15.9,
# R18.17). The harness enforces that in-process; this script enforces it around the
# process, so a test reaching the network through a path the harness does not patch fails
# rather than passing quietly. Run it after dependencies are installed and before the
# suite, on a throwaway machine: it rewrites the OUTPUT chain of the host it runs on.
#
# Loopback stays reachable, because the offline suite talks to local stubs and a local
# DynamoDB.
#
# The GitHub Actions runner communicates with the server via HTTPS (port 443) to hosts
# named in ACTIONS_RUNTIME_URL and ACTIONS_RESULTS_URL. These specific IPs are resolved
# before the denial is applied and allowed through. This is tighter than allowing all
# ESTABLISHED connections: only the runner's own endpoints are exempted, and only on 443.
# A test that opens a new connection to any other host — including on port 443 — is
# rejected immediately.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
	echo "deny-egress: re-running under sudo" >&2
	exec sudo -n "$0" "$@"
fi

for command in iptables ip6tables; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "deny-egress: $command is not available on this host" >&2
		exit 1
	fi
done

# ---------------------------------------------------------------------------
# Resolve the GitHub Actions runner's communication endpoints.
# The runner needs HTTPS (443) to these hosts for heartbeats, log uploads,
# and result reporting. Without this, the runner loses communication and
# GitHub marks the job as failed.
# ---------------------------------------------------------------------------
allowed_ips=()

resolve_host() {
	local url="$1"
	if [ -z "$url" ]; then return; fi
	# Extract hostname from URL (strip scheme and path)
	local host
	host=$(echo "$url" | sed -E 's|^https?://||; s|[:/].*||')
	if [ -z "$host" ]; then return; fi
	# Resolve to IPv4 addresses
	local ips
	ips=$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u) || true
	for ip in $ips; do
		allowed_ips+=("$ip")
		echo "deny-egress: allowing $ip ($host) on port 443" >&2
	done
}

resolve_host "${ACTIONS_RUNTIME_URL:-}"
resolve_host "${ACTIONS_RESULTS_URL:-}"
resolve_host "${ACTIONS_CACHE_URL:-}"

# ---------------------------------------------------------------------------
# Apply the iptables rules.
#
# Order matters: loopback first, then the runner's specific IPs on 443 only,
# then REJECT everything else. REJECT rather than DROP so a refused connection
# fails immediately instead of hanging until its timeout.
# ---------------------------------------------------------------------------
iptables --policy OUTPUT ACCEPT
iptables --flush OUTPUT
iptables --append OUTPUT --out-interface lo --jump ACCEPT

for ip in "${allowed_ips[@]}"; do
	iptables --append OUTPUT --destination "$ip" --protocol tcp --dport 443 --jump ACCEPT
done

iptables --append OUTPUT --jump REJECT --reject-with icmp-admin-prohibited

ip6tables --policy OUTPUT ACCEPT
ip6tables --flush OUTPUT
ip6tables --append OUTPUT --out-interface lo --jump ACCEPT
ip6tables --append OUTPUT --jump REJECT --reject-with icmp6-adm-prohibited

# The denial is verified rather than assumed, which is the whole point of the script.
if curl --silent --show-error --max-time 5 --output /dev/null https://example.com 2>/dev/null; then
	echo "deny-egress: outbound access is still available; refusing to continue" >&2
	exit 1
fi

echo "deny-egress: outbound network access denied, runner endpoints exempted, loopback retained"
