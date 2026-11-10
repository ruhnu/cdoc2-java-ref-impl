#!/usr/bin/env bash
# End-to-end demo of "ruhnu/did/" DID recipients (and a "ruhnu/pk/" regression check), see README.md.
#
# Starts Postgres, the Liquibase migration and an HTTPS DID host in Docker, two shares servers as JVM processes,
# and private ssh-agents, then runs each step with cdoc2-cli and checks the result. Exits non-zero if any check
# fails. Cleans up on exit; KEEP=1 leaves everything running and prints how to stop it.
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REF_IMPL=$(cd "$HERE/../.." && pwd)
SHARES_SERVER_DIR=${SHARES_SERVER_DIR:-$REF_IMPL/../cdoc2-shares-server}
SHARES_SERVER_DIR=$(cd "$SHARES_SERVER_DIR" && pwd)
# short path: ssh-agent sockets must fit into sun_path
DEMO_WORK=${DEMO_WORK:-$(mktemp -d /tmp/ruhnu-did-demo.XXXXXX)}
export DEMO_WORK
COMPOSE=(docker compose -f "$HERE/docker-compose.yml")

DID_PORT=8444
DID="did:web:localhost%3A${DID_PORT}:p:alice"
DID_DOC="$DEMO_WORK/did-docs/p/alice/did.json"
TRUSTSTORE=$REF_IMPL/cdoc2-cli/config/localhost/clienttruststore.jks
TRUSTSTORE_JVM=(-Djavax.net.ssl.trustStore="$TRUSTSTORE" -Djavax.net.ssl.trustStorePassword=passwd
    -Djavax.net.ssl.trustStoreType=JKS)

FAILED=0
step() { printf '\n=== %s\n' "$*"; }
pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; FAILED=1; }

cleanup() {
    if [[ "${KEEP:-}" == 1 ]]; then
        printf '\nKEEP=1: left running. Stop with:\n  kill %s; ssh-agent -k (SSH_AGENT_PID=...); ' \
            "$(cat "$DEMO_WORK"/*.pid 2>/dev/null | tr '\n' ' ')"
        printf 'DEMO_WORK=%s %s down -v\n' "$DEMO_WORK" "${COMPOSE[*]}"
        return
    fi
    for pidfile in "$DEMO_WORK"/*.pid; do
        [[ -f "$pidfile" ]] && kill "$(cat "$pidfile")" 2>/dev/null
    done
    "${COMPOSE[@]}" down -v >/dev/null 2>&1
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || { echo "missing: $1"; exit 2; }; }
for tool in java mvn docker ssh-agent ssh-add ssh-keygen python3 openssl curl; do need "$tool"; done

# --- build -------------------------------------------------------------------------------------------------

step "Build (cdoc2-openapi and cdoc2-auth feat/add-did-recipient must be installed in ~/.m2)"
SERVER_JAR=$(ls "$SHARES_SERVER_DIR"/shares-server/target/cdoc2-shares-server-*.jar 2>/dev/null | grep -v -e original -e -tests | head -1)
if [[ -z "$SERVER_JAR" || "${REBUILD:-}" == 1 ]]; then
    (cd "$SHARES_SERVER_DIR" && mvn -B -q install -DskipTests) || exit 2
    SERVER_JAR=$(ls "$SHARES_SERVER_DIR"/shares-server/target/cdoc2-shares-server-*.jar | grep -v -e original -e -tests | head -1)
fi
CLI_JAR=$(ls "$REF_IMPL"/cdoc2-cli/target/cdoc2-cli-*.jar 2>/dev/null | grep -v -e original -e -tests | head -1)
if [[ -z "$CLI_JAR" || "${REBUILD:-}" == 1 ]]; then
    (cd "$REF_IMPL" && mvn -B -q install -DskipTests) || exit 2
    CLI_JAR=$(ls "$REF_IMPL"/cdoc2-cli/target/cdoc2-cli-*.jar | grep -v -e original -e -tests | head -1)
fi
docker build -q -t ruhnu-demo/cdoc2-shares-server-liquibase:local \
    "$SHARES_SERVER_DIR/server-db/src/main/resources/db" >/dev/null || exit 2
echo "shares server: $SERVER_JAR"
echo "cdoc2-cli:     $CLI_JAR"
echo "work dir:      $DEMO_WORK"

cdoc2() {
    # cdoc2-cli trusts the DID host through the JVM default trust store
    java "${TRUSTSTORE_JVM[@]}" -jar "$CLI_JAR" "$@"
}

# --- environment ---------------------------------------------------------------------------------------------

step "Start Postgres, Liquibase, DID host and two shares servers"
mkdir -p "$DEMO_WORK/did-host-tls" "$(dirname "$DID_DOC")"
# the DID host reuses the shares servers' "localhost" test certificate, which TRUSTSTORE trusts
openssl pkcs12 -in "$SHARES_SERVER_DIR/keys/cdoc2server.p12" -passin pass:passwd -nokeys -clcerts \
    -out "$DEMO_WORK/did-host-tls/cert.pem" 2>/dev/null
openssl pkcs12 -in "$SHARES_SERVER_DIR/keys/cdoc2server.p12" -passin pass:passwd -nocerts -nodes \
    -out "$DEMO_WORK/did-host-tls/key.pem" 2>/dev/null
chmod a+r "$DEMO_WORK"/did-host-tls/*.pem
python3 "$HERE/make-did-json.py" "$DID" > "$DID_DOC"

"${COMPOSE[@]}" up -d --wait postgres did-host >/dev/null || exit 2
"${COMPOSE[@]}" run --rm liquibase >"$DEMO_WORK/liquibase.log" 2>&1 \
    || { cat "$DEMO_WORK/liquibase.log"; exit 2; }

KEYS=$SHARES_SERVER_DIR/keys
cat > "$DEMO_WORK/shares-server.properties" <<EOF
server.ssl.key-store-type=PKCS12
server.ssl.key-store=$KEYS/cdoc2server.p12
server.ssl.key-store-password=passwd
server.ssl.key-alias=cdoc2-server
server.ssl.enabled=true
server.ssl.enabled-protocols=TLSv1.3
server.max-http-request-header-size=16000
logging.level.root=info
cdoc2.auth-x5c.revocation-checks-enabled=false
cdoc2.auth-x5c.sign-cert-forbidden=true
key-share-nonce.expired.clean-up.cron=0 0/5 * * * ?
key-share.expired.clean-up.cron=0 0/5 * * * ?
session-nonce.expired.clean-up.cron=0 0/5 * * * ?
key-share.default-expiration-duration=P1095D
key-share.max-expiration-duration=P1825D
spring.ssl.bundle.jks.trusted-issuers.truststore.location=$SHARES_SERVER_DIR/shares-server/src/test/resources/trusted-issuers/test_trusted_issuers.jks
spring.ssl.bundle.jks.trusted-issuers.truststore.password=changeit
spring.ssl.bundle.jks.trusted-issuers.truststore.type=jks
spring.ssl.bundle.jks.trusted-infra.truststore.location=$KEYS/cdoc2_infra_truststore.jks
spring.ssl.bundle.jks.trusted-infra.truststore.password=changeit
spring.ssl.bundle.jks.trusted-infra.truststore.type=jks
spring.datasource.url=jdbc:postgresql://localhost:5433/cdoc2-shares
spring.datasource.username=postgres
spring.datasource.password=secret
spring.datasource.driver-class-name=org.postgresql.Driver
management.server.ssl.enabled=true
management.server.ssl.key-store-type=PKCS12
management.server.ssl.key-store=$KEYS/cdoc2server.p12
management.server.ssl.key-store-password=passwd
management.server.ssl.key-alias=cdoc2-server
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never
management.endpoints.metrics.username=username
management.endpoints.metrics.password=password
app.restclient.auth-server.hostUri=https://localhost:7500
app.restclient.rp-server.hostUri=https://localhost:7600
cdoc2.rp-server.rp-name=DEMO
cdoc2.rp-server.scheme-name=smart-id-demo
# ruhnu fork features, DID recipients for the demo DID host
cdoc2.ruhnu.enabled=true
cdoc2.ruhnu.did.allowed-hosts=localhost:$DID_PORT
EOF

start_server() { # name port management-port
    # the shares server fetches DID documents trusting TRUSTSTORE (JVM default trust store)
    java "${TRUSTSTORE_JVM[@]}" -jar "$SERVER_JAR" \
        --spring.config.additional-location="file:$DEMO_WORK/shares-server.properties" \
        --server.port="$2" --management.server.port="$3" >"$DEMO_WORK/$1.log" 2>&1 &
    echo $! >"$DEMO_WORK/$1.pid"
}
start_server shares1 8443 18443
start_server shares2 8442 18442
for port in 18443 18442; do
    for _ in $(seq 120); do
        curl -sfk "https://localhost:$port/actuator/health" 2>/dev/null | grep -q UP && break
        sleep 1
    done
    curl -sfk "https://localhost:$port/actuator/health" | grep -q UP \
        || { echo "shares server on management port $port did not start"; tail -40 "$DEMO_WORK"/shares*.log; exit 2; }
done
pass "environment is up"

sed "s#config/localhost/clienttruststore.jks#$TRUSTSTORE#" \
    "$REF_IMPL/cdoc2-cli/config/localhost/key-shares.properties" >"$DEMO_WORK/key-shares.properties"
KS="-Dkey-shares.properties=$DEMO_WORK/key-shares.properties"

new_agent() { # name -> socket path; generates key <name> (P-256) and adds it
    local sock="$DEMO_WORK/$1.sock"
    ssh-agent -a "$sock" >"$DEMO_WORK/$1.agent" && \
        awk -F'[=;]' '/SSH_AGENT_PID/ {print $2}' "$DEMO_WORK/$1.agent" >"$DEMO_WORK/$1-agent.pid"
    ssh-keygen -q -t ecdsa -b 256 -N "" -C "$1@demo" -f "$DEMO_WORK/$1" >/dev/null
    SSH_AUTH_SOCK="$sock" ssh-add -q "$DEMO_WORK/$1" 2>/dev/null
    echo "$sock"
}
ALICE_SOCK=$(new_agent alice)
echo "secret payload $(date)" >"$DEMO_WORK/payload.txt"

CONTAINER="$DEMO_WORK/secret.cdoc2"
decrypt() { # socket out-dir -> exit code; decrypts $CONTAINER, stderr in $DEMO_WORK/decrypt.err
    rm -rf "$2"; mkdir -p "$2"
    cdoc2 decrypt -f "$CONTAINER" --ssh-agent="$1" -o "$2" "$KS" \
        >"$DEMO_WORK/decrypt.out" 2>"$DEMO_WORK/decrypt.err"
}
expect_decrypted() { # label socket
    if decrypt "$2" "$DEMO_WORK/out" && cmp -s "$DEMO_WORK/payload.txt" "$DEMO_WORK/out/payload.txt"; then
        pass "$1"
    else
        fail "$1"; cat "$DEMO_WORK/decrypt.err"
    fi
}
expect_refused() { # label socket expected-message
    if decrypt "$2" "$DEMO_WORK/out"; then
        fail "$1: decryption succeeded"
    elif grep -q -- "$3" "$DEMO_WORK/decrypt.err"; then
        pass "$1: $(grep -m1 '^ERROR: ' "$DEMO_WORK/decrypt.err")"
    else
        fail "$1: expected \"$3\""; cat "$DEMO_WORK/decrypt.err"
    fi
}

# --- 6.2 encrypt to the DID, decrypt, audit log ----------------------------------------------------------------

step "6.2 Encrypt to $DID and decrypt through ssh-agent"
python3 "$HERE/make-did-json.py" "$DID" "$DEMO_WORK/alice.pub" >"$DID_DOC"
if cdoc2 create -f "$DEMO_WORK/secret.cdoc2" --did "$DID" "$KS" "$DEMO_WORK/payload.txt" >"$DEMO_WORK/create.out" 2>&1 \
    && grep -q "^Pinned ruhnu/did/$DID/hash/" "$DEMO_WORK/create.out"; then
    pass "created, $(grep Pinned "$DEMO_WORK/create.out")"
else
    fail "create"; cat "$DEMO_WORK/create.out"; exit 1
fi
cdoc2 info -f "$DEMO_WORK/secret.cdoc2" | grep "SSH key via DID"
expect_decrypted "decrypted with Alice's agent key" "$ALICE_SOCK"
for server in shares1 shares2; do
    if grep -q "Key share released: .*recipient=ruhnu/did/$DID/hash/" "$DEMO_WORK/$server.log"; then
        pass "$server audit log: $(grep -m1 -o 'Key share released: .*' "$DEMO_WORK/$server.log")"
    else
        fail "$server audit log has no ruhnu/did/ release"
    fi
done

# --- 6.3 revocation ------------------------------------------------------------------------------------------

step "6.3 Revoke: remove Alice's key from the DID document"
python3 "$HERE/make-did-json.py" "$DID" >"$DID_DOC"
expect_refused "refused after revocation" "$ALICE_SOCK" "no longer listed in the DID document"
python3 "$HERE/make-did-json.py" "$DID" "$DEMO_WORK/alice.pub" >"$DID_DOC"
expect_decrypted "decrypted again after restoring the key" "$ALICE_SOCK"

# --- 6.4 DID host outage -------------------------------------------------------------------------------------

step "6.4 Outage: stop the DID host"
"${COMPOSE[@]}" stop did-host >/dev/null 2>&1
expect_refused "refused while the DID host is down" "$ALICE_SOCK" "could not reach the DID host"
"${COMPOSE[@]}" start did-host >/dev/null 2>&1
for _ in $(seq 30); do
    curl -sfk "https://localhost:$DID_PORT/p/alice/did.json" >/dev/null && break
    sleep 1
done
expect_decrypted "decrypted again after the DID host is back" "$ALICE_SOCK"

# --- 6.5 compromised DID host --------------------------------------------------------------------------------

step "6.5 Compromised DID host: Mallory's key added to Alice's DID document"
MALLORY_SOCK=$(new_agent mallory)
python3 "$HERE/make-did-json.py" "$DID" "$DEMO_WORK/alice.pub" "$DEMO_WORK/mallory.pub" >"$DID_DOC"
expect_refused "Mallory's agent can't decrypt the existing container" "$MALLORY_SOCK" \
    "No matching key found in ssh-agent"
if SSH_AUTH_SOCK="$MALLORY_SOCK" java -cp "$CLI_JAR" "$HERE/AttackerFetch.java" \
    "$DEMO_WORK/secret.cdoc2" "$DID" "$TRUSTSTORE" passwd >"$DEMO_WORK/attacker.out" 2>&1; then
    pass "Mallory's own DID token for Alice's shares is refused: $(tail -1 "$DEMO_WORK/attacker.out")"
else
    fail "Mallory's DID token"; cat "$DEMO_WORK/attacker.out"
fi
expect_decrypted "Alice still decrypts" "$ALICE_SOCK"

# --- 6.6 phase 1 regression ----------------------------------------------------------------------------------

step "6.6 Phase 1 regression: encrypt to Alice's SSH public key (ruhnu/pk/)"
CONTAINER="$DEMO_WORK/secret-pk.cdoc2"
if cdoc2 create -f "$CONTAINER" --ssh-pubkey "$DEMO_WORK/alice.pub" "$KS" "$DEMO_WORK/payload.txt" \
    >"$DEMO_WORK/create.out" 2>&1; then
    pass "created ruhnu/pk/ container"
else
    fail "create ruhnu/pk/"; cat "$DEMO_WORK/create.out"
fi
cdoc2 info -f "$CONTAINER" | grep "SSH public key"
expect_decrypted "decrypted ruhnu/pk/ container" "$ALICE_SOCK"

for agentpid in "$DEMO_WORK"/*-agent.pid; do kill "$(cat "$agentpid")" 2>/dev/null; rm -f "$agentpid"; done
echo
if [[ $FAILED == 0 ]]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit $FAILED
