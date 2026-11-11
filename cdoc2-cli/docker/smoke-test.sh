#!/usr/bin/env bash
# Smoke test of a ruhnu-cli image, without shares servers:
#  1. the CLI runs and prints its version
#  2. decrypt --ssh-agent reaches an ssh-agent mounted into the container: the fixture is encrypted to a key
#     whose private key was discarded, so the CLI must list the agent's keys and report that none matches
#  3. without an agent, decrypt --ssh-agent reports that ssh-agent is not available
# Usage: smoke-test.sh <image>
# Needs docker, ssh-agent, ssh-add and ssh-keygen.
set -euo pipefail

image="${1:?usage: $0 <image>}"
fixture_dir="$(cd "$(dirname "$0")/smoke-test" && pwd)"

# short directory: Unix socket paths are limited to 108 bytes
tmp="$(mktemp -d /tmp/ruhnu-cli-smoke.XXXXXX)"
agent_pid=""
cleanup() {
    if [[ -n "$agent_pid" ]]; then
        kill "$agent_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# runs the image as the calling user, without network, with the fixture mounted read-only
run_cli() {
    docker run --rm --network none --user "$(id -u):$(id -g)" -v "$fixture_dir:/work:ro" "$@"
}

echo "== $image: --version"
version_out="$(run_cli "$image" --version 2>&1)" || fail "--version exited with $?: $version_out"
grep -q '^cdoc2-cli version: ' <<<"$version_out" || fail "--version printed no cdoc2-cli version: $version_out"
echo "$version_out"

echo "== $image: decrypt --ssh-agent with a mounted agent that doesn't hold the fixture key"
ssh-agent -a "$tmp/agent.sock" </dev/null >"$tmp/agent.env" 2>/dev/null
agent_pid="$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' "$tmp/agent.env")"
ssh-keygen -q -t ecdsa -b 256 -N '' -C ruhnu-cli-smoke-test -f "$tmp/key"
SSH_AUTH_SOCK="$tmp/agent.sock" ssh-add -q "$tmp/key"
if agent_out="$(run_cli -v "$tmp/agent.sock:/ssh-agent.sock" -e SSH_AUTH_SOCK=/ssh-agent.sock \
    "$image" decrypt --ssh-agent -f /work/ssh-recipient.cdoc2 -o /tmp 2>&1)"; then
    fail "decrypt succeeded, expected a missing key: $agent_out"
fi
grep -q 'No matching key found in ssh-agent' <<<"$agent_out" \
    || fail "decrypt did not reach the agent: $agent_out"
grep 'No matching key found in ssh-agent' <<<"$agent_out"

echo "== $image: decrypt --ssh-agent without an agent"
if noagent_out="$(run_cli "$image" decrypt --ssh-agent -f /work/ssh-recipient.cdoc2 -o /tmp 2>&1)"; then
    fail "decrypt succeeded without an agent: $noagent_out"
fi
grep -q 'ssh-agent is not available' <<<"$noagent_out" \
    || fail "expected 'ssh-agent is not available': $noagent_out"
grep 'ssh-agent is not available' <<<"$noagent_out"

echo "OK: $image passed the smoke test"
