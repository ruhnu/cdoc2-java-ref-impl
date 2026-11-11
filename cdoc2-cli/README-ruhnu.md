# cdoc2-cli: Ruhnu additions

This fork of cdoc2-java-ref-impl adds SSH public key and DID recipients to cdoc2-cli, and publishes the CLI as the
container image `ghcr.io/ruhnu/ruhnu-cli`. Everything else is in [README.md](README.md).

## Encryption and decryption with SSH key (ssh-agent)

Run the commands below from the cdoc2-cli directory, as in [README.md](README.md).

A container can be encrypted to an SSH public key and decrypted with the matching private key in
`ssh-agent`. The key is split into key shares on the shares servers, as for Smart-ID/Mobile-ID, but the
shares are released to whoever proves possession of the SSH key: the client signs an auth token through
`ssh-agent` (`$SSH_AUTH_SOCK`). No Smart-ID, Mobile-ID, RP server or auth server is involved, and the private
key never leaves the agent.

Requirements:
* the SSH key is ECDSA P-256 (`ecdsa-sha2-nistp256`). Ed25519 and RSA keys are not supported yet
* every configured shares server runs with SSH public key recipients enabled
  (`cdoc2.ruhnu.enabled=true`, see cdoc2-shares-server admin guide). The shares servers decide how long
  the shares are kept (default 14 days); after that the container can't be decrypted
* `key-shares.properties` lists the shares servers, as for Smart-ID/Mobile-ID

Create a key and load it into the agent, if you don't have one:

```
ssh-keygen -t ecdsa -b 256 -f ~/.ssh/id_ecdsa
ssh-add ~/.ssh/id_ecdsa
```

Encrypt to a public key file (`-ssh`, `--ssh-pubkey`, can be repeated for several recipients):

```
java -jar target/cdoc2-cli-*.jar create \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  --ssh-pubkey ~/.ssh/id_ecdsa.pub \
  -f /tmp/ssh.cdoc2 README.md
```

or to a public key line, for example a key in your agent (`ssh-add -L` lists all agent keys, one per line;
give one line per `--ssh-pubkey`):

```
java -jar target/cdoc2-cli-*.jar create \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  --ssh-pubkey "$(ssh-add -L | grep -m1 ecdsa-sha2-nistp256)" \
  -f /tmp/ssh.cdoc2 README.md
```

A shorter share lifetime can be requested with `-sexp`, `--share-expiry` (format `P(n)DT(n)H(n)M(n)S`, for
example `P3D` for 3 days). It must be positive. The shares servers cut longer requests to their maximum, and
the CLI prints a warning with the actual expiry time for each server that did:

```
java -jar target/cdoc2-cli-*.jar create \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  --ssh-pubkey ~/.ssh/id_ecdsa.pub --share-expiry P3D \
  -f /tmp/ssh.cdoc2 README.md
```

`info` shows the SSH recipient with its key fingerprint (same as `ssh-add -l` shows) and recipient identifier:

```
java -jar target/cdoc2-cli-*.jar info -f /tmp/ssh.cdoc2
SSH public key: SN:ruhnu/pk:SHA256:ILaep1/NfsYICEypSkuVoSj0tD6P+nvxnABaRhsg+uc, TYPE:auth, V:1 (recipient: ruhnu/pk/AAAAE2Vj...)
```

Decrypt with the matching key in the agent (`-ssh`, `--ssh-agent`). The CLI picks the container's SSH
recipient whose key the agent holds:

```
java -jar target/cdoc2-cli-*.jar decrypt \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  --ssh-agent -f /tmp/ssh.cdoc2 -o /tmp
```

`--ssh-agent-socket /path/to/agent.sock`, used instead of `--ssh-agent`, uses another agent socket instead
of `$SSH_AUTH_SOCK`.

Errors are reported without a stack trace, with exit code 1:

| Message                                     | Cause                                                                       |
|---------------------------------------------|-----------------------------------------------------------------------------|
| `ssh-agent is not available`                | `$SSH_AUTH_SOCK` is not set, or the agent socket can't be connected         |
| `No matching key found in ssh-agent`        | the agent doesn't hold any of the container's SSH keys (fingerprints listed); nothing is sent to the shares servers |
| `ssh-agent refused to sign`                 | the agent declined, for example the `ssh-add -c` confirmation was refused   |
| `Invalid SSH public key: ... not supported` | `create` with a key type other than `ecdsa-sha2-nistp256`                   |

Security notes:
* Anyone who can use your agent can decrypt: a forwarded agent (`ssh -A`) can be used by root on the remote
  host. Prefer decrypting locally, and add the key with `ssh-add -c` (confirm every use) or use a FIDO key.
* To revoke access before the shares expire, the shares must be deleted on at least one shares server.

## Encryption and decryption with a DID (ssh-agent)

A container can also be encrypted to a `did:web` DID, such as `did:web:example.org:p:alice`. `create` fetches
the DID document (`https://example.org/p/alice/did.json`) and pins every ECDSA P-256 key it lists under
`authentication`: one recipient per key, `ruhnu/did/<did>/hash/<fingerprint>`, where the fingerprint is the
key's `ssh-keygen -l` SHA256 fingerprint. Decryption works as for SSH public keys, through `ssh-agent`, but every
shares server also fetches the DID document and releases its share only while the document still lists the key.
Removing the key from the DID document revokes access at once. Because the container pins the key's fingerprint,
a compromised DID host can block access but can't add a key that opens existing containers. The DID host is
trusted at the moment of encryption, so check the pinned fingerprints that `create` prints.

Requirements, in addition to those for SSH public keys:
* every configured shares server allows the DID host (`cdoc2.ruhnu.did.allowed-hosts`, see the
  cdoc2-shares-server admin guide) and can reach it over HTTPS
* the DID host's TLS certificate is trusted by the JVM (for a private CA, `-Djavax.net.ssl.trustStore=...`)
* the shares servers keep DID recipient shares for their global lifetime (by default up to 3 years)

A DID document listing the key, in `publicKeyJwk` form (`kty` `EC`, `crv` `P-256`):

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.org:p:alice",
  "verificationMethod": [{
    "id": "did:web:example.org:p:alice#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:example.org:p:alice",
    "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}
  }],
  "authentication": ["#key-1"]
}
```

Encrypt to a DID (`-did`, `--did`, can be repeated, and combined with other recipients):

```
java -jar target/cdoc2-cli-*.jar create \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  --did did:web:example.org:p:alice \
  -f /tmp/did.cdoc2 README.md
Pinned ruhnu/did/did:web:example.org:p:alice/hash/ILaep1_NfsYICEypSkuVoSj0tD6P-nvxnABaRhsg-uc (SHA256:ILaep1/NfsYICEypSkuVoSj0tD6P+nvxnABaRhsg+uc)
```

Keys the document lists in another form or of another type (for example Ed25519) are skipped with a
`WARNING`. `--share-expiry` works as for SSH public keys.

`info` shows the DID and the pinned key's fingerprint:

```
java -jar target/cdoc2-cli-*.jar info -f /tmp/did.cdoc2
SSH key via DID: SN:ruhnu/did:did:web:example.org:p:alice#SHA256:ILaep1/..., TYPE:auth, V:1 (recipient: ruhnu/did/did:web:example.org:p:alice/hash/ILaep1_..., DID did:web:example.org:p:alice, key SHA256:ILaep1/...)
```

Decrypt with `--ssh-agent`, exactly as for SSH public keys. The CLI matches the agent's keys against the
container's SSH and DID recipients by fingerprint; it doesn't fetch the DID document itself.

Errors, in addition to those for SSH public keys:

| Message                                                               | Cause                                                                     |
|-----------------------------------------------------------------------|---------------------------------------------------------------------------|
| `Only did:web DIDs are supported`, `... is not a valid did:web DID`, `DID is too long` | `create` with a DID that can't be used; nothing is uploaded |
| `The DID document of ... was not found`                               | `create`: the DID host answered, but not with this DID's document         |
| `The DID host of ... could not be reached`                            | `create`: connection failure, timeout, TLS failure or HTTP 5xx/429        |
| `... lists no supported key`                                          | `create`: no ECDSA P-256 `publicKeyJwk` key under `authentication`        |
| `refused to save key share: HTTP 400; the DID host may not be allowed there` | `create`: a shares server doesn't allow the DID host               |
| `... the key is no longer listed in the DID document of ...`          | `decrypt`: a shares server refused the share (404): revoked, expired or deleted |
| `... could not reach the DID host of ...; try again later`            | `decrypt`: a shares server couldn't fetch the DID document (503)          |

## Docker image (SSH key recipients)

The container image `ghcr.io/ruhnu/ruhnu-cli` runs cdoc2-cli without a local Java installation. It is
published for linux/amd64 and linux/arm64 when cdoc2-java-ref-impl is tagged: `v*` tags as `:<tag>` and
`:latest`, `dev-*` tags as `:<tag>`. It supports encrypting to SSH public keys and decrypting through your
ssh-agent, as described above. Smart-ID, Mobile-ID and ID-card are not supported in the image.

The examples below use `:latest`. To use an exact version, or while no `v*` release exists yet (and so no
`:latest`), pick an available tag from the `ruhnu-cli` package, listed under "Packages" on
https://github.com/ruhnu/cdoc2-java-ref-impl (directly:
https://github.com/ruhnu/cdoc2-java-ref-impl/pkgs/container/ruhnu-cli), and use it in place of `latest`,
for example `ghcr.io/ruhnu/ruhnu-cli:dev-cli-image-1`. With the `ruhnu` function below, set
`RUHNU_CLI_IMAGE` to that image.

The container sees only what you mount into it, and paths in arguments and in `key-shares.properties` are
paths in the container:
* `/work`: your files, for example the current directory
* `/config`: `key-shares.properties` and the truststore it names, for example `~/.config/cdoc2`
* `/ssh-agent.sock`: your agent socket, with `SSH_AUTH_SOCK` pointing to it (decryption only)

Run the container as your own user (`--user "$(id -u):$(id -g)"`): ssh-agent only serves the user who
started it, and decrypted files are then owned by you.

`localhost` in the container is the container itself. If the shares servers run on your machine, as in
`config/localhost`, add `--network host` (Linux).

For example, with `~/.config/cdoc2/key-shares.properties` containing
`cdoc2.key-shares.client.ssl.trust-store=/config/clienttruststore.jks` and the truststore next to it:

```
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v "$HOME/.config/cdoc2:/config:ro" \
  ghcr.io/ruhnu/ruhnu-cli:latest create -Dkey-shares.properties=/config/key-shares.properties \
  --ssh-pubkey "$(ssh-add -L | grep -m1 ecdsa-sha2-nistp256)" -f ssh.cdoc2 README.md

mkdir -p out
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -v "$HOME/.config/cdoc2:/config:ro" \
  -v "$SSH_AUTH_SOCK:/ssh-agent.sock" -e SSH_AUTH_SOCK=/ssh-agent.sock \
  ghcr.io/ruhnu/ruhnu-cli:latest decrypt -Dkey-shares.properties=/config/key-shares.properties \
  --ssh-agent -f ssh.cdoc2 -o out
```

A shell function `ruhnu` shortens this to `ruhnu <command> <options>`, for files in the current directory.
Set `RUHNU_CLI_IMAGE` to use another image tag:

```
ruhnu() {
  local cmd="$1"; shift
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD:/work" -v "$HOME/.config/cdoc2:/config:ro" \
    -v "$SSH_AUTH_SOCK:/ssh-agent.sock" -e SSH_AUTH_SOCK=/ssh-agent.sock \
    "${RUHNU_CLI_IMAGE:-ghcr.io/ruhnu/ruhnu-cli:latest}" \
    "$cmd" -Dkey-shares.properties=/config/key-shares.properties "$@"
}

mkdir -p out && ruhnu decrypt --ssh-agent -f ssh.cdoc2 -o out
```

While the container runs, it can ask your agent to sign with any key the agent holds. Prefer a dedicated
agent that holds only the cdoc2 key (`ssh-agent -a <socket>`, then `ssh-add` the key with that
`SSH_AUTH_SOCK`), or add the key with `ssh-add -c`.

To build the image locally, from the cdoc2-java-ref-impl directory:

```
mvn -pl cdoc2-cli -am package -DskipTests
version=$(mvn -q -pl cdoc2-cli help:evaluate -Dexpression=project.version -DforceStdout)
rm -rf cdoc2-cli/target/docker && mkdir cdoc2-cli/target/docker
cp "cdoc2-cli/target/cdoc2-cli-$version.jar" cdoc2-cli/target/docker/cdoc2-cli.jar
cp cdoc2-cli/docker/Dockerfile cdoc2-cli/target/docker/
docker build -t ruhnu-cli:local cdoc2-cli/target/docker
cdoc2-cli/docker/smoke-test.sh ruhnu-cli:local
```
