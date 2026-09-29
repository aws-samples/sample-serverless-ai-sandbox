#!/usr/bin/env bash
# kiro-classification: public
#
# Denies new outbound connections except loopback, then proves the denial holds.
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
# Connections established before the denial (the GitHub Actions runner's heartbeat,
# log uploads, and result reporting) are allowed to continue via ESTABLISHED,RELATED.
# Only NEW outbound connections are rejected — the test suite cannot open new network
# connections to any host.

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

# REJECT rather than DROP: a refused connection fails immediately, so a test that reaches
# for the network reports an error instead of hanging until its timeout.
# ESTABLISHED,RELATED keeps the runner's pre-existing connections alive (heartbeat, logs).
iptables --policy OUTPUT ACCEPT
iptables --flush OUTPUT
iptables --append OUTPUT --out-interface lo --jump ACCEPT
iptables --append OUTPUT --match state --state ESTABLISHED,RELATED --jump ACCEPT
iptables --append OUTPUT --jump REJECT --reject-with icmp-admin-prohibited

ip6tables --policy OUTPUT ACCEPT
ip6tables --flush OUTPUT
ip6tables --append OUTPUT --out-interface lo --jump ACCEPT
ip6tables --append OUTPUT --match state --state ESTABLISHED,RELATED --jump ACCEPT
ip6tables --append OUTPUT --jump REJECT --reject-with icmp6-adm-prohibited

# The denial is verified rather than assumed, which is the whole point of the script.
if curl --silent --show-error --max-time 5 --output /dev/null https://example.com 2>/dev/null; then
	echo "deny-egress: outbound access is still available; refusing to continue" >&2
	exit 1
fi

echo "deny-egress: outbound network access denied, loopback and established connections retained"
