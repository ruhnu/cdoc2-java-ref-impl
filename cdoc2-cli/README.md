# Building & Running

To run without building, download latest version of cdoc2-cli.jar from https://github.com/orgs/open-eid/packages 

## Building
Run from cdoc2-java-ref-impl parent directory
```
mvn clean package
```

Will create `cdoc2-cli/target/cdoc2-cli-<version>.jar`

## Running
Run from cdoc2-cli directory

Latest help can be seen by running:
```
java -jar target/cdoc2-cli-<version>.jar
```

where `<version>` must be replaced with the latest version built. Example `0.0.12-SNAPSHOT`

Sample generated CDOC2 documents are located at `cdoc2-java-ref-impl/test/testvectors`

Commands for creating and decrypting sample files using cdoc2-cli are in `cdoc2-java-ref-impl/test/generate_documents.sh`


### Encryption
To create:
- Output file `/tmp/mydoc.cdoc`
- with generated private key
- to recipient `keys/bob_pub.pem`
- to encrypt file 'README.md'

```
java -jar target/cdoc2-cli-*.jar create --file /tmp/mydoc.cdoc2 -p keys/bob_pub.pem README.md
```

### Encryption with server scenario
Server must be running, see cdoc2-capsule-server/README.md for starting the server

To store keys in key server, specify addition `--server` option:

When encrypting for est-eid card, `-r` <id-code> can be used
```
java -jar target/cdoc2-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc2 -r 38001085718 README.md
```

Optionally cdoc2-cli also supports encrypting with "soft" key or certificate

Public key (`-p`)
```
java -jar target/cdoc2-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc2 -p keys/cdoc2client_pub.key README.md
```

Certificate (`-c` option):
```
java -jar target/cdoc2-cli-*.jar create --server=config/localhost/localhost.properties -f /tmp/localhost.cdoc2 -c keys/cdoc2client-certificate.pem README.md
```

Key capsule expiration date can be requested when adding expiry duration:
```
-exp P365D
```
Default expiration duration will be used if it is not requested by the client. Default and max 
expiration durations are configurable values in put-server and get-server.


### Encryption with symmetric key and password

Generate key with openssl (minimum length 32 bytes):
```
openssl rand -base64 32
`HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE=`
```

Base64 encoded keys must be prefixed with 'base64,', so that key becomes "base64,HHeUrHfo+bCZd//gGmEOU2nA5cgQolQ/m18UO/dN1tE="

Encrypt with generated key and label 'label_b64secret':
```
java -jar target/cdoc2-cli-*.jar create --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=" -f /tmp/symmetric.cdoc2 README.md
```

Or secret read from file (so that secret is not exposed through process list)
```
java -jar target/cdoc2-cli-*.jar create @keys/b64secret.option -f /tmp/symmetric.cdoc2 README.md
```

```
cat keys/b64secret.option --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
```

Or encrypt with password clear text (note, that password also can be encoded to base64 format, as secret):
```
java -jar target/cdoc2-cli-*.jar create --password "passwordlabel:myPlainTextPassword" -f /tmp/password.cdoc2 README.md
```

Decryption is done with the same label and key used for encryption
```
java -jar target/cdoc2-cli-*.jar decrypt @keys/b64secret.option -f /tmp/symmetric.cdoc2 -o /tmp
```

Or with the same label and password used for encryption:
```
java -jar target/cdoc2-cli-*.jar decrypt --password "passwordlabel:myPlainTextPassword" -f /tmp/password.cdoc2 --output /tmp
```

If cdoc2 file contains only one password, then specifying label is not required and label can be omitted:
```
java -jar target/cdoc2-cli-*.jar decrypt --password ":myPlainTextPassword" -f /tmp/password.cdoc2 --output /tmp
```


Or with the same label and secret used for encryption:
```
java -jar target/cdoc2-cli-*.jar decrypt --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0=" -f /tmp/symmetric.cdoc2 --output /tmp
```

Key and label can be safely stored in a password manager.


### Encryption with Smart ID

Current encryption/decryption implementation of cdoc2 container with Smart ID supports only Estonian
personal ID codes.

```
java \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  -jar target/cdoc2-cli-*.jar \
  create \
  --smart-id=40504040001 \
  -f /tmp/smartid.cdoc2 \
  README.md
```

Multiple ID codes are allowed to be sent for encryption:

```
java -jar target/cdoc2-cli-*.jar create -sid=38001085718 -sid=47101010033 \
 -f /tmp/smartid.cdoc2 README.md
```

Key shares properties can be sent externally by adding following options (the same 
for decryption):

`-Dkey-shares.properties=config/localhost/key-shares.properties`


### Encryption with Mobile ID

Current encryption/decryption implementation of cdoc2 container with Mobile ID supports only 
Estonian personal ID codes.

```
java -jar target/cdoc2-cli-*.jar create --mobile-id=51307149560 -f /tmp/mobileid.cdoc2 README.md
```

Multiple ID codes are allowed to be sent for encryption:

```
java \
  `-Dkey-shares.properties=config/localhost/key-shares.properties` \
  -jar target/cdoc2-cli-*.jar create -mid=51307149560 -mid=60001017869 \
  -f /tmp/mobileid.cdoc2 README.md
```

Key shares properties can be sent externally by adding following options (the same
for decryption):

`-Dkey-shares.properties=config/localhost/key-shares.properties`


### Encryption and decryption with SSH key (ssh-agent)

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
example `P3D` for 3 days). The shares servers cut longer requests to their maximum:

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

`--ssh-agent=/path/to/agent.sock` uses another agent socket instead of `$SSH_AUTH_SOCK`.

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

### Docker image (SSH key recipients)

The container image `ghcr.io/ruhnu/ruhnu-cli` runs cdoc2-cli without a local Java installation. It is
published for linux/amd64 and linux/arm64 when cdoc2-java-ref-impl is tagged: `v*` tags as `:<tag>` and
`:latest`, `dev-*` tags as `:<tag>`. It supports encrypting to SSH public keys and decrypting through your
ssh-agent, as described above. Smart-ID, Mobile-ID and ID-card are not supported in the image.

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

A shell function makes this read like the plain CLI, for files in the current directory. Set
`RUHNU_CLI_IMAGE` to use another image tag:

```
cdoc2() {
  local cmd="$1"; shift
  docker run --rm --user "$(id -u):$(id -g)" \
    -v "$PWD:/work" -v "$HOME/.config/cdoc2:/config:ro" \
    -v "$SSH_AUTH_SOCK:/ssh-agent.sock" -e SSH_AUTH_SOCK=/ssh-agent.sock \
    "${RUHNU_CLI_IMAGE:-ghcr.io/ruhnu/ruhnu-cli:latest}" \
    "$cmd" -Dkey-shares.properties=/config/key-shares.properties "$@"
}

mkdir -p out && cdoc2 decrypt --ssh-agent -f ssh.cdoc2 -o out
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


### Decryption
To decrypt:
- CDOC2 file `/tmp/mydoc.cdoc2`
- with decryption private EC key `keys/bob.pem`
- to output directory `/tmp`

```
java -jar target/cdoc2-cli-*.jar decrypt --file /tmp/mydoc.cdoc2 -k keys/bob.pem --output /tmp
```

or with Smart-ID for Estonian personal ID code:

```
java \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  -Dauth-server.properties=config/localhost/auth-server.properties \
  -Drp-server.properties=config/localhost/rp-server.properties \
  -jar target/cdoc2-cli-*.jar \
  decrypt \
  -sid=40504040001 \
  -f /tmp/smartid.cdoc2 \
  --output /tmp
```

or with Mobile-ID for Estonian personal ID code and Estonian phone number with country code `+372`:

```
java \
  -Dkey-shares.properties=config/localhost/key-shares.properties \
  -Dauth-server.properties=config/localhost/auth-server.properties \
  -Drp-server.properties=config/localhost/rp-server.properties \
  -jar target/cdoc2-cli-*.jar \
  decrypt \
  -mid=51307149560 -mid-phone=+37269930366 \
  -f /tmp/mobileid.cdoc2 \
  --output /tmp
```

### Decrypting with server scenario
Server must be running, see cdoc2-capsule-server/README.md for starting the server

To decrypt CDOC2 document that has its keys distributed through key server, cdoc2-cli must have `--server` option:

Configuration for id-card (certificate for mutual TLS and private key is read from smart-card)
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/localhost/localhost.properties -f /tmp/localhost_id-card.cdoc2 -o /tmp/
```

It is also possible to decrypt documents created with "soft" keys, but configuration for mutual TLS (properties file) and
key (read separately from a file) must match. Also, server must be configured to trust client certificate used for
mutual TLS.
```
java -jar target/cdoc2-cli-*.jar decrypt --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc2 -k keys/cdoc2client_priv.key -o /tmp/
```


### Re-encryption with password for long time storage

First encrypt the document:
```
java -jar target/cdoc2-cli-*.jar create --secret "mylongpasswd:longstringthatIcanremember,butothersdon'tknow" -f /tmp/symmetric.cdoc2 README.md
```

Create different directory for re-encrypted container:
```
mkdir -p /tmp/cdoc2
```

Then re-encrypt it with password for long-term storage:
```
java -jar target/cdoc2-cli-*.jar re-encrypt --encpassword "passwordlabel:myPlainTextPassword" --secret "mylongpasswd:longstringthatIcanremember,butothersdon'tknow" -f /tmp/symmetric.cdoc2 --output /tmp/cdoc2
```

For testing decryption ensure the correct re-encrypted container location:
```
java -jar target/cdoc2-cli-*.jar decrypt --password "passwordlabel:myPlainTextPassword" -f /tmp/cdoc2/symmetric.cdoc2 --output /tmp/cdoc2
```

### List

```
java -jar target/cdoc2-cli-*.jar list --file /tmp/mydoc.cdoc2 -k keys/bob.pem
```

or with server scenario:

```
java -jar target/cdoc2-cli-*.jar list --server=config/localhost/localhost_pkcs12.properties -f /tmp/localhost.cdoc2 -k keys/cdoc2client_priv.key
```

or with password:
```
java -jar target/cdoc2-cli-*.jar list --file /tmp/symmetric.cdoc2 --password "passwordlabel:myPlainTextPassword"
```

or with secret:
```
java -jar target/cdoc2-cli-*.jar list --file /tmp/symmetric.cdoc2 --secret "label_b64secret:base64,aejUgxxSQXqiiyrxSGACfMiIRBZq5KjlCwr/xVNY/B0="
```

### List recipients

List recipients. Prints recipient types and key labels from CDOC2 header.

```
java -jar target/cdoc2-cli-*.jar info -f /tmp/id.cdoc2
```


## ID-kaart (Est-id secure card)


### Encrypting for ID-card owner

cdoc2-cli can download authentication certificate (Isikutuvastus PIN1) from SK and Zetes LDAP directory
https://github.com/SK-EID/LDAP/wiki/Knowledge-Base

To create cdoc for recipient with id code 37101010021 use:
```
java -jar target/cdoc2-cli-*.jar create --file /tmp/mydoc.cdoc2 -r 37101010021 README.md
```

[TODO: Onece the SK LDAP is updated, remove this section]: #
> **NOTE:** Currently the SK LDAP service is using TLS_RSA_WITH_AES_256_GCM_SHA384 which is 
> disabled by some Java Development Kit (JDK).
>
> If the encryption gives `javax.naming.CommunicationException: simple bind failed: esteid.ldap.sk.ee:636` error,
> then in the `jdk/conf/security/java.security` remove the `TLS_RSA_*` in the `jdk.tls.disabledAlgorithms`.
> 
> A script to do it automatically:
> ``` 
> sed -i '/^jdk\.tls\.disabledAlgorithms=/{:loop; /\\$/{N; b loop}; s/TLS_RSA_\*,[ \t]*//g}' /usr/lib/jvm/java-17-openjdk-amd64/conf/security/java.security
> ```


### Decrypting with ID-card

To decrypt:
- CDOC file mydoc.cdoc2
- use private key from ID-card slot 0 (Isikutuvastus PIN1)
- Decrypt files from cdoc2 file into current directory
```
java -jar target/cdoc2-cli-*.jar decrypt -f mydoc.cdoc2
```

### Certificate extraction

* Run DigiDoc4 client
* Crypto -> Add file (choose random file)
* Recipients -> Certificate from card -> click on certificate -> Show Certificate -> Save

Saved certificate will be .cer file (same as der)

or

* Run DigiDoc4 client
* Crypto -> Add file (choose random file)
* Recipients -> Enter personal code -> Search -> Show Certificate -> Save


### Encrypting documents with certificate

To create:
- Output file `/tmp/mydoc.cdoc2`
- with generated private key
- to recipient with certificate `keys/cdoc2client-certificate.pem` (DER or PEM formats are supported)
- to encrypt file 'README.md'

```
java -jar target/cdoc2-cli-*.jar create --file /tmp/mydoc.cdoc2 -c keys/cdoc2client-certificate.pem README.md
```

Decrypt created container with private key:
```
java -jar target/cdoc2-cli-*.jar decrypt -f /tmp/mydoc.cdoc2 -k keys/cdoc2client_priv.key --output /tmp
```

### Troubleshooting ID-card

Verify that DigiDoc4 client is running and can access ID-card

cdoc2-cli will try to configure itself automatically. If OpenSC library is installed to non-standard location, then
specify its location by setting 'pkcs11-library' property:

```
java -jar target/cdoc2-cli-*.jar decrypt -Dpkcs11-library=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so -f mydoc.cdoc2
```

More tips for debugging ID-card related issues are provided in cdoc2-lib/pkcs11.README file


## Other configuration options

Set with -D option

```
java -jar target/cdoc2-cli-*.jar decrypt -Dee.cyber.cdoc2.overwrite=false -f mydoc.cdoc2
```

#### pkcs11-library
PKCS11 library location. Default is platform specific

Common OpenSC library locations:

* For Windows, it could be C:\Windows\SysWOW64\opensc-pkcs11.dll
* For Linux, it could be /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
* For OSX, it could be /usr/local/lib/opensc-pkcs11.so

## SafeNet eToken support

Requirements:
* OpenSC is installed
* SafeNet Authentication Client (provides the pkcs11 library) is installed.
  See https://knowledge.digicert.com/generalinformation/INFO1982.html for details.

To find the slot for the SafeNet eToken, execute:

```
pkcs11-tool --module /usr/lib/libeToken.so -L
```

List entries on the eToken device:

```
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -list
```

Export Certificate from the SafeNet eToken device:

```
keytool -providerclass sun.security.pkcs11.SunPKCS11 -providerarg opensc-safenet.cfg -storetype PKCS11 -storepass YOUR-SAFENET-PIN -alias YOUR_ENTRY_ALIAS -exportcert -rfc -file etoken-cert.pem
```

Encrypt certificate as described in the "Encrypting documents with certificate" section.

List files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

```
java -jar target/cdoc2-cli-*.jar list -f file-for-etoken.cdoc2 -Dpkcs11-library=/usr/lib/libeToken.so -a cdoc2-test --slot 1 --crypto-stick SECP256R1
```

Decrypt files encrypted for the eToken device by specifying pkcs11 library, slot and key alias:

```
java -jar target/cdoc2-cli-*.jar decrypt -f file-for-etoken.cdoc2 -Dpkcs11-library=/usr/lib/libeToken.so -a cdoc2-test --slot 1 --crypto-stick SECP256R1
```

The java PKCS#11 interface does not support the OAEP padding, 
so the implementation uses the `sun.security.pkcs11.wrapper` private methods to directly communicate with the crypto stick.
For this, it is necessary to add these to the java classpath with `--add-exports`.

List files encrypted for the RSA eToken device by specifying pkcs11 library, slot and key alias:

```
java \
  --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  --add-opens=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  -jar target/cdoc2-cli-*.jar \
  list \
  --server=config/localhost/localhost.properties \
  -f /tmp/localhost.cdoc2 \
  -Dpkcs11-library=/usr/lib/libeToken.so \
  -a cdoc2-test \
  --slot 1 \
  --crypto-stick RSA4096
```

Decrypt files encrypted for the RSA eToken device by specifying pkcs11 library, slot and key alias:

```
java \
  --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  --add-opens=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED \
  -jar target/cdoc2-cli-*.jar \
  decrypt \
  -Dpkcs11-library=/usr/lib/libeToken.so \
  --server=config/localhost/localhost.properties \
  -f /tmp/localhost.cdoc2 \
  -o /tmp \
  -a cdoc2-test \
  --slot 1 \
  --crypto-stick RSA4096
```

#### ee.cyber.cdoc2.overwrite 
When decrypting, is overwriting files allowed. Default is false

#### ee.cyber.cdoc2.maxDiskUsagePercentage
default 98.0

Decrypting will be stopped if disk usage is over  maxDiskUsagePercentage


#### ee.cyber.cdoc2.tarEntriesThreshold
default 1000

Decrypting will be stopped if container contains over tarEntriesThreshold entries (files)


#### ee.cyber.cdoc2.compressionThreshold
default 10.0

Decrypting will be stopped if compressed file compression ratio is over compressionThreshold

#### ee.cyber.cdoc2.key-label.machine-readable-format.enabled
default true

Key label format can be defined while encrypting. Machine parsable format is enabled by default
and free text format is allowed if the property disabled.
Machine-readable format is following, where `<data>` is the key label value:
```
data:[<mediatype>][;base64],<data>
```

#### ee.cyber.cdoc2.key-label.file-name.added
default true

Key label `<data>` field contains different parameters. File name is one of them. For security 
purpose it can be hidden in configuration. File name is added by default.

#### ee.cyber.key-shares.properties
CLI option which indicates the path to key capsule client key-shares properties file.
- ##### ee.cyber.key-shares.urls
  Key shares servers URL-s, separated by comma `","`
- ##### ee.cyber.key-shares.min_num
  Minimum quantity of key shares servers
- ##### ee.cyber.key-shares.algorithm
  Key shares algorithm

#### ee.cyber.smart-id.properties
CLI option which indicates the path to smart-id properties file.
- ##### ee.cyber.smartid.client.hostUrl
  Smart ID client host URL
- ##### ee.cyber.smartid.client.relyingPartyUuid
  Smart ID client relying party UUID
- ##### ee.cyber.smartid.client.relyingPartyName
  Smart ID client relying party name
- ##### ee.cyber.smartid.client.ssl.trust-store-password
  Smart ID client SSL trust store password
