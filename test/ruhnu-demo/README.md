# DID recipient demo (ruhnu fork)

End-to-end demo of `ruhnu/did/<did:web DID>/hash/<fingerprint>` recipients: encrypt to a DID, decrypt through
`ssh-agent`, revoke by editing the DID document, survive a DID host outage, and show that a key a compromised
DID host adds can't open an existing container. It also re-runs the phase 1 `ruhnu/pk/` flow.

```
test/ruhnu-demo/demo.sh
```

Each step prints `PASS`/`FAIL`; the script exits non-zero if any check fails and cleans up on exit (`KEEP=1`
leaves everything running).

## What it starts

| Component            | Where                              | Notes                                                       |
|----------------------|------------------------------------|-------------------------------------------------------------|
| Postgres             | Docker, `localhost:5433`           | shared by both shares servers                                |
| Liquibase migration  | Docker, image built from `cdoc2-shares-server/server-db` | applies the shares server schema   |
| DID host (nginx)     | Docker, `https://localhost:8444`   | serves `$DEMO_WORK/did-docs`, TLS with the test `localhost` certificate |
| shares server 1 and 2 | JVM processes, `8443` and `8442` (management `18443`, `18442`) | `cdoc2.ruhnu.enabled=true`, `cdoc2.ruhnu.did.allowed-hosts=localhost:8444` |
| ssh-agents           | `$DEMO_WORK/alice.sock`, `mallory.sock` | P-256 keys generated with `ssh-keygen`                   |

The DID is `did:web:localhost%3A8444:p:alice`, so its document is `https://localhost:8444/p/alice/did.json`. The
shares servers run on the host, not in Docker, so that this DID resolves the same way for them and for
`cdoc2-cli`. Both trust the DID host's certificate through the JVM default trust store
(`-Djavax.net.ssl.trustStore=cdoc2-cli/config/localhost/clienttruststore.jks`).

## Steps

1. **Encrypt and decrypt**: `make-did-json.py` writes a DID document listing Alice's key; `cdoc2 create --did`
   pins it, `cdoc2 decrypt --ssh-agent` decrypts, and both servers' logs show
   `Key share released: ... recipient=ruhnu/did/...`.
2. **Revocation**: the DID document no longer lists the key, so decryption fails with "no longer listed in the
   DID document"; restoring the key makes it work again.
3. **Outage**: the DID host is stopped, so decryption fails with "could not reach the DID host"; it works again
   once the host is back.
4. **Compromised DID host**: Mallory's key is added to Alice's DID document. Mallory's agent can't decrypt the
   container (no matching recipient), and `AttackerFetch.java` shows that a validly signed DID token for
   Mallory's own key gets `404` for each of Alice's shares, because the container pins Alice's fingerprint.
5. **Phase 1 regression**: encrypt to Alice's SSH public key (`--ssh-pubkey`) and decrypt.

## Requirements

- Linux or macOS with Docker (Compose v2), Java 21, Maven, OpenSSH (`ssh-agent`, `ssh-add`, `ssh-keygen`),
  python3, openssl and curl
- the sibling checkout `../cdoc2-shares-server` (override with `SHARES_SERVER_DIR`), on `feat/add-did-recipient`
- `cdoc2-openapi` and `cdoc2-auth` on `feat/add-did-recipient` installed into `~/.m2` (`mvn install` in each),
  so that the shares server and cdoc2-cli build. The script builds the shares server and cdoc2-cli if their jars
  are missing (`REBUILD=1` forces it)

Free ports needed: 5433, 8442, 8443, 8444, 18442, 18443.
