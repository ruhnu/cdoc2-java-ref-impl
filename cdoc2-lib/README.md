# CDOC

CDOC stands for 'Crypto Digidoc', encrypted file transmission format used in the [Estonian eID](https://github.com/open-eid) ecosystem.

([Digidoc](https://www.id.ee/en/article/digidoc-container-format-life-cycle-2/) is digital signature format specific to Estonia)

* CDOC1 - Unofficial term for all (XML-ENC based) CDOC formats preceding CDOC2.
* [CDOC2](https://open-eid.github.io/CDOC2) is a new version of CDOC, featuring additional security
  measures with optional server backend and support for long term cryptography and Smart-ID/Mobile-ID 
  (auth based encryption)

CDOC1 and CDOC2 version are not compatible.

End-user software to create/decrypt CDOC1/CDOC2: https://github.com/open-eid/DigiDoc4-Client

Additional background info can be found in [RIA CDOC2 presentation](https://www.youtube.com/watch?v=otrO2A6TuGQ)
and [id.ee CDOC 2.0 article](https://www.id.ee/artikkel/cdoc-2-0/)

# Format differences between CDOC1 and CDOC2

## CDOC1

CDOC1 is xml document, examples can be found [here](https://github.com/open-eid/cdoc4j/blob/master/src/test/resources/cdoc/)

```
~/workspace/cdoc2-java-ref-impl/cdoc2-example-app/src/test/resources/cdoc$ head -1 valid_cdoc11_ECC.cdoc
<?xml version="1.0" encoding="UTF-8"?><denc:EncryptedData xmlns:denc="http://www.w3.org/2001/04/xmlenc#" MimeType="application/octet-stream">
```

[CDOC1 specification](https://www.id.ee/wp-content/uploads/2020/06/sk-cdoc-1.0-20120625_en.pdf) and
Java library [cdoc4j](https://github.com/open-eid/cdoc4j)

To create/decrypt CDOC1 documents see [cdoc4j: Examples of how to use it](https://github.com/open-eid/cdoc4j/wiki/Examples-of-how-to-use-it)

## CDOC2

CDOC2 is binary document, where first 4 bytes are `0x43, 0x44, 0x4f, 0x43` or `CDOC` in ASCII:
```
~/workspace/cdoc2-java-ref-impl/test/testvectors$ hd ec_simple.cdoc2 
00000000  43 44 4f 43 02 00 00 01  6c 0c 00 00 00 08 00 0c  |CDOC....l.......|
```

[CDOC2 specification](https://open-eid.github.io/CDOC2) and Java library
[cdoc2-java-ref-impl](https://github.com/open-eid/cdoc2-java-ref-impl)

# cdoc2-java-ref-impl

`cdoc2-java-ref-impl` is a [repository](https://github.com/open-eid/cdoc2-java-ref-impl) that contains `cdoc2-lib` and related submodules required for
creating/decrypting CDOC2 documents. To use modules from `cdoc2-java-ref-impl`:

## Configure GitHub Maven package registry

To use `cdoc2-java-ref-impl` as Maven dependency you need to [create a GitHub personal access token](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-to-github-packages)
with `read:packages` scope.

Configure [Maven settings.xml](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry#authenticating-with-a-personal-access-token)
or [configure Gradle](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-gradle-registry)

Example `<profile>` section of `settings.xml` for using cdoc2 dependencies:
```xml
  <profile>
      <id>github</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo1.maven.org/maven2</url>
        </repository>
        <repository>
          <id>github</id>
          <url>https://maven.pkg.github.com/open-eid/cdoc2-java-ref-impl</url>
        </repository>
      </repositories>
  </profile>
```

Test that you have configured your Maven `settings.xml` correctly (from `cdoc2-example-app` directory):

```
./mvnw dependency::get -Dartifact=ee.cyber.cdoc2:cdoc2-lib:2.0.0
```
```
[INFO] Resolving ee.cyber.cdoc2:cdoc2-lib:jar:2.0.0 with transitive dependencies
Downloading from central: https://repo1.maven.org/maven2/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom
Downloading from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom
Downloaded from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.pom (3.2 kB at 2.3 kB/s)
Downloading from central: https://repo1.maven.org/maven2/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar
Downloading from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar
Downloaded from github: https://maven.pkg.github.com/open-eid/cdoc2-capsule-server/ee/cyber/cdoc2/cdoc2-lib/2.0.0/cdoc2-lib-2.0.0.jar (157 kB at 136 kB/s)
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

Latest version of `cdoc2-lib` can be found [here](https://github.com/open-eid/cdoc2-java-ref-impl/packages/2223168)

## cdoc2-lib usage

Define `cdoc2-lib` dependency in your `pom.xml`:
```xml
<dependency>
    <groupId>ee.cyber.cdoc2</groupId>
    <artifactId>cdoc2-lib</artifactId>
    <version>3.7.2</version>
</dependency>
```

[Full example](https://github.com/open-eid/cdoc2-java-ref-impl/blob/master/cdoc2-example-app/pom.xml)

### Configure cdoc2-lib with properties

#### Initialize configuration for server scenarios:

```java
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;

public KeyCapsuleClientFactory initKeyCapsuleClientFactory(String keyServerPropertiesFile) {
   KeyCapsuleClientConfiguration config = KeyCapsuleClientConfiguration.load(
           PropertiesLoader.loadProperties(keyServerPropertiesFile));
   return KeyCapsuleClientImpl.createFactory(config);
}
```


Alternatively:

```java
import ee.cyber.cdoc2.services.Cdoc2Services;

// normally initialized through -D option to java process
System.setProperty("key-capsule.properties", "classpath:localhost.properties");
Services services = Cdoc2Services.initFromSystemProperties();
KeyCapsuleClientFactory capsuleClientFactory = services.get(KeyCapsuleClientFactory.class);
```

Or:

```java
import ee.cyber.cdoc2.services.Cdoc2Services;

Properties p = new Properties();
p.setProperty("key-capsule.properties", "classpath:localhost.properties");
Services services = Cdoc2Services.initFromProperties(p);
KeyCapsuleClientFactory capsuleClientFactory = services.get(KeyCapsuleClientFactory.class);
```

### Services configuration

There are different "services" used by `cdoc2-lib`, most are configured through properties. For
up to date of list all "services" and their configurations see `Cdoc2Services` class source code.

Local "services" can be started by running `docker compose `

#### KeyCapsuleClientFactory and KeyCapsuleClient: key-capsule.properties

`KeyCapsuleClientFactory` and `KeyCapsuleClient` are used to connect to `cdoc2-capsule-server` that
is used for encryption/decryption with server scenarios (id-card/smart-card).

Difference is that `KeyCapsuleClient` is used for encryption, where mTLS is not required 
and `KeyCapsuleClientFactory` is used for decryption, where mutual TLS is required. 

They share configuration file - `key-capsule.properties`

If only encryption functionality is wanted, then it may make sense initialize only `KeyCapsuleClient`, by defining 
`key-capsule-post.properties` as initializing `KeyCapsuleClientFactory` may require PIN for smart-card.

Example `KeyCapsuleClientFactory` configuration: [localhost/localhost.properties](../cdoc2-cli/config/localhost/localhost.properties)

Local `cdoc2-capsule-server` can be started by running:
```bash
cd ../test/config/capsule-server
docker compose up
```

#### KeySharesClientFactory: key-shares.properties

`KeySharesClientFactory` is used for authentication based encryption/decryption (Smart-ID/Mobile-ID).
It will connect to `cdoc2-shares-server` servers.

Example configuration: [localhost/key-shares.properties](../cdoc2-cli/config/localhost/key-shares.properties)

Local `cdoc2-shares-server` can be started by running:
```bash
cd ../test/config/shares-server
docker compose up
```

#### SmartIdClient: smart-id.properties

Used when decrypting CDOC2 created for Smart-ID recipient

[Smart-ID demo environment](https://github.com/SK-EID/smart-id-documentation/wiki/Smart-ID-demo) configuration: 
[smart-id.properties](../cdoc2-cli/config/smart-id/smart-id.properties)

#### MobileIdClient: mobile-id.properties

Used when decrypting CDOC2 created for Mobile-ID recipient

[Mobile-ID demo environment](https://github.com/SK-EID/MID/wiki/Environment-technical-parameters#demo) 
configuration: [smart-id.properties](../cdoc2-cli/config/mobile-id/mobile-id.properties)


#### Updating Smart ID or Mobile ID certificates in tests
Integration tests check the validity of server's certificates and will fail after their expiration.
When certificate has expired there is needed to replace it with new certificate in the trust store. 
1. Obtain the new certificate from SK.
2. Remove expired certificate from the trust store.

   List all certificates in trust store and find an alias for expired one:
   
   `keytool -list -v -keystore smartid_demo_server_trusted_ssl_certs.jks -storepass passwd`
   
   Delete expired certificate:

    `keytool -delete -noprompt -alias <EXPIRED_CERTIFICATE_ALIAS> -keystore smartid_demo_server_trusted_ssl_certs.jks 
    -storepass passwd`

3. Import new valid certificate into the trust store:
   `keytool -import -trustcacerts -file <NEW_CERTIFICATE>.pem.crt -keystore 
   smartid_demo_server_trusted_ssl_certs.jks -alias <NEW_CERTIFICATE_ALIAS> -storepass passwd`


### To create CDOC2 document with password:
```java
        File cdoc2FileToCreate = Paths.get("/tmp/first.cdoc2").toFile();
        File payloadFile1 = Paths.get("some_file1.txt").toFile();
        File payloadFile2 = Paths.get("some_file2.txt").toFile();
        File[] payloadFiles = new File[]{payloadFile1, payloadFile2};
        char[] password = "myPlainTextPassword".toCharArray(); // don't store password in String in production code
        String keyLabel = "labelFromExample";
 
        EncryptionKeyMaterial km = EncryptionKeyMaterial.fromPassword(password, keyLabel);
        
        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(payloadFiles))
            .withRecipients(List.of(km));
        
        builder.buildToFile(cdoc2FileToCreate);
```

### To decrypt with password:
```java
        Path cdoc2FileToDecrypt = Paths.get("/tmp/first.cdoc2");
        Path destDir = Paths.get("/tmp");
        char[] password = "myPlainTextPassword".toCharArray(); // don't store password in String in production code
        String keyLabel = "labelFromExample";

        List<String> extractedFileNames = new CDocDecrypter()
            .withCDoc(cdoc2FileToDecrypt.toFile())
            .withRecipient(DecryptionKeyMaterial.fromPassword(password, keyLabel))
            .withDestinationDirectory(destDir.toFile())
            .decrypt();
```

### To create cdoc2 document for id-card:

```java
        File cdoc2FileToCreate = Paths.get("/tmp/second.cdoc2").toFile();
        String identificationCode = "3..."; // your id-code
        File[] payloadFiles = new File[]{};//add some files

        List<EncryptionKeyMaterial> etsiRecipients = new EstEncKeyMaterialBuilder()
            .fromCertDirectory(this.recipient.identificationCodes)
            .build();

        CDocBuilder builder = new CDocBuilder()
            .withPayloadFiles(Arrays.asList(payloadFiles))
            .withRecipients(recipients);
        
        builder.buildToFile(cdoc2FileToCreate);
```

**Note**: this works only for end user id-cards. It doesn't work for test id-cards as test-id card
certificates are not in the live LDAP servers, see [SK LDAP](https://github.com/SK-EID/LDAP/wiki/Knowledge-Base). 
To use test id-card, extract certificate from id-card and encrypt with certificate. 
There is no difference between real and test id-cards when decrypting.

### To decrypt with id-card you need a smart device and physical ID card:

Using id-card requires that you have openSC PKCS11 drivers installed. These are usually installed
by installing https://www.id.ee/en/article/install-id-software/ Before trying to decrypt CDOC2 files
with `cdoc2-lib` verify that you can access id-card with [DigiDoc4](https://github.com/open-eid/DigiDoc4-Client)

```java
        Path cdoc2FileToDecrypt = Paths.get("/tmp/second.cdoc2");
        Path destDir = Paths.get("/tmp");
        Integer slot = 0;
        String alias = "Isikutuvastus";

        // load keys by asking pin code interactively
        KeyPair keyPair = Pkcs11Tools.loadFromPKCS11Interactively(
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // pkcs11 driver location, differs on different platforms 
            slot,
            alias,
            null
        );
        
        // or load keys with a given pin code
        char[] pin;
        KeyPair keyPair = Pkcs11Tools.loadFromPKCS11WithPin(
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // pkcs11 driver location, differs on different platforms 
            slot,
            new KeyStore.PasswordProtection(pin),
            alias
        );
        
        DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromKeyPair(keyPair);
        
        List<String> extractedFiles = new CDocDecrypter()
            .withCDoc(cdoc2FileToDecrypt.toFile())
            .withRecipient(dkm)
            .withDestinationDirectory(destDir.toFile())
            .decrypt();
```

`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` is location of OpenSC pkcs11 driver library. Some info
on setting up pcks11 on Ubuntu can be found in [pkcs11.README](https://github.com/open-eid/cdoc2-java-ref-impl/blob/master/cdoc2-lib/pkcs11.README)

## CDOC2 server scenario usage

Most cdoc2 documents created by DigiDoc4 will use [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)

### Checking CDOC2 recipients

To determine, what kind of recipient can decrypt CDOC2 document and if [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)
was used, see source code for [cdoc2-cli info](https://github.com/open-eid/cdoc2-java-ref-impl/blob/f91a917fc0fb47f35e9e4f69de4d0108b620d00d/cdoc2-cli/src/main/java/ee/cyber/cdoc2/cli/commands/CDocInfoCmd.java#L46)

### Create CDOC2 document with key material stored in server.

To create CDOC2 document with server scenario, [cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server) client needs to be configured.
Easiest is to use one of existing properties files from [cdoc2-cli/config](https://github.com/open-eid/cdoc2-java-ref-impl/tree/master/cdoc2-cli/config/)
directory and `.withKeyCapsuleClient` method (or `.withServices` where `Services` object `.hasService(KeyCapsuleClient.class)` ):

```java
import ee.cyber.cdoc2.client.KeyCapsuleClient;
import ee.cyber.cdoc2.client.KeyCapsuleClientImpl;
import ee.cyber.cdoc2.config.KeyCapsuleClientConfiguration;
import ee.cyber.cdoc2.config.PropertiesLoader;

File cdoc2FileToCreate = Paths.get("/tmp/second.cdoc2").toFile();
String identificationCode = "3..."; // your id-code
String keyServerPropertiesFile = "/path/to/cdoc2-cli/conf/id.properties";
Properties p = PropertiesLoader.loadProperties(keyServerPropertiesFile);
KeyCapsuleClient capsuleClient = KeyCapsuleClientImpl.create(KeyCapsuleClientConfiguration.load(p), false);

// download certificates from SK  or Zetes LDAP and creates EncryptionKeyMaterial from them
// works for Estonian ID code only, implement similar class for other national ID codes or different LDAP
List<EncryptionKeyMaterial> recipients = new EstEncKeyMaterialBuilder()
    .fromCertDirectory(new String[]{identificationCode}).build();

CDocBuilder builder = new CDocBuilder()
        .withKeyCapsuleClient(capsuleClient) // will use server scenario
        .withPayloadFiles(Arrays.asList(payloadFiles))
        .withRecipients(recipients);

builder.buildToFile(cdoc2FileToCreate);
```
**Note**: `cdoc2-cli/config` contains usually several properties files. For id-card usage, use one with
the shortest name (without `_pkcs12` or `_p12` in name).

Uploading key material to server allows to invalidate CDOC2 documents that are may be affected from
future security vulnerability like [ROCA vulnerability](https://en.wikipedia.org/wiki/ROCA_vulnerability)

In non-server scenarios sender public key material is included in CDOC2 itself. For server scenarios
sender public key material is uploaded to server and recipient needs first to download the
sender public key material and then needs to decrypt CDOC2 with private key. Even when data stored
in server gets compromised, it doesn't grant access to CDOC2 documents as final decryption is done
with recipient private key (id-card).

### Create CDOC2 document with key material stored in server and can be decrypted with id-card/Smart-ID/Mobile-ID

Smart-ID/Mobile-ID do not support encryption/decryption directly. For each Smart-ID/Mobile-ID 
recipient symmetric key is created and that key split into parts. Parts are uploaded to different 
`cdoc2-shares-server` servers. Each `cdoc2-shares-server` is maintained by different organization (so compromising one 
`cdoc2-shares-server` doesn't reveal decryption key). To decrypt CDOC2 created for Smart-ID/Mobile-ID,
recipient needs to authenticate himself with supported auth means (Smart-ID/Mobile-ID) and download
key parts

```java
   File cdoc2FileToCreate = Paths.get("/tmp/second3.cdoc2").toFile();
   String identificationCode = "38001085718"; // Jõeorg, replace with real id-code that is present in SK or Zetes LDAP
   File[] payloadFiles = new File[]{};//add some files
   
   // normally initialized through -D option to java process
   System.setProperty("key-capsule-post.properties","classpath:localhost.properties"); // from classpath
   System.setProperty("key-shares.properties","config/key_shares-test.properties"); // from file system

   // alternatively use Cdoc2Services.initFromProperties(Properties)
   Services services = Cdoc2Services.initFromSystemProperties();
   
   List<EncryptionKeyMaterial> encKeyMaterial = new EstEncKeyMaterialBuilder()
           .fromCertDirectory(new String[]{identificationCode}) // will download recipient certificate and add public key based recipient
           .forAuthMeans(new String[]{identificationCode}) // will create authentication based recipient, that can be decrypted with SID/MID
           .build();

   CDocBuilder builder = new CDocBuilder()
           .withPayloadFiles(files)
           .withRecipients(encKeyMaterial)
           .withServices(services);
   
   builder.buildToFile(cdoc2FileToCreate);
```

### Decrypting with key material from the server

Similar to previous example, to decrypt cdoc2 with server recipient,
[cdoc2-capsule-server](https://github.com/open-eid/cdoc2-capsule-server)client needs to be configured.

```java
Path cdoc2FileToDecrypt = Paths.get("/tmp/second.cdoc2");
Path destDir = Paths.get("/tmp");
Integer slot = 0;
String alias = "Isikutuvastus";
  
System.setProperty("key-capsule.properties","classpath:localhost.properties");

Services services = Cdoc2Services.initFromSystemProperties();

DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromKeyPair(
        Pkcs11Tools.loadFromPKCS11Interactively(
                "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so", // pkcs11 driver location, differs on different platforms 
                slot,
                alias,
                null
        )
);

List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withServices(services)
        .withRecipient(dkm)
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```

**Note**: `pkcs11-library` location can also be specified as Java system property 
(`-Dpkcs11-library=<path>` or `System.setProperty("pkcs11-library", "<path>")`), 
when not specified explicitly as method parameter. If `pkcs11-library` system property is not set,
then pkcs11 library is looked for from [default locations](https://github.com/open-eid/cdoc2-java-ref-impl/blob/ae1351db7e13c3ede58a48757ae53c2c80166a70/cdoc2-lib/src/main/java/ee/cyber/cdoc2/crypto/Pkcs11Tools.java#L404)

### Latest server configuration

Latest server configuration is available through https://id.eesti.ee/config.json

### Decrypting with Smart-ID

```java
String idCode = "51307149560";

SemanticsIdentifier semId = new SemanticsIdentifier(
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE,
        idCode
        );

AuthenticationIdentifier decryptAuthIdentifier = 
        new AuthenticationIdentifier(AuthenticationType.SID, semId);

// normally initialized through -D option to java process
System.setProperty("key-shares.properties","config/key_shares-test.properties");
System.setProperty("smart-id.properties","classpath:smart-id/smart_id-test.properties"); 
Services services = Cdoc2Services.initFromSystemProperties();

DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(decryptAuthIdentifier);

List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withServices(services)
        .withRecipient(dkm)
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```


### Decrypting with Mobile-ID

```java
String idCode = "51307149560";
String phoneNumber = "+37269930366";

SemanticsIdentifier semId = new SemanticsIdentifier(
        SemanticsIdentifier.IdentityType.PNO,
        SemanticsIdentifier.CountryCode.EE,
        idCode
        );

AuthenticationIdentifier decryptAuthIdentifier = 
        new AuthenticationIdentifier(AuthenticationType.MID, semId, phoneNumber);

// normally initialized through -D option to java process
System.setProperty("key-shares.properties","config/key_shares-test.properties");
System.setProperty("mobile-id.properties","classpath:mobile-id/mobile_id-test.properties"); 
Services services = Cdoc2Services.initFromSystemProperties();

DecryptionKeyMaterial dkm = DecryptionKeyMaterial.fromAuthMeans(decryptAuthIdentifier);

List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withServices(services)
        .withRecipient(dkm)
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```


### User interaction with Smart ID and Mobile ID clients
Smart ID and Mobile ID clients interact with user by display messages and verification code.
Available interactions are implemented in a class `InteractionParams`, which can be of
following types `InteractionParams.InteractionType`:
* DISPLAY_TEXT_AND_PIN
* CONFIRMATION_MESSAGE
* VERIFICATION_CODE_CHOICE
* CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE

Initialized `InteractionParams` will be transferred to Smart ID and Mobile ID clients while
authenticating.

`InteractionParams` can be configured by initializing `KeyShareDecryptionKeyMaterial`
with method `InteractionParamsConfigurable.init()` while decrypting:
```java
    private static void addInteractionParameters(File cdocFile, DecryptionKeyMaterial dkm) {
        if (dkm instanceof InteractionParamsConfigurable paramsConfigurable) {

            InteractionParams interactionParams = (cdocFile == null)
                ? InteractionParams.displayTextAndPin()
                : InteractionParams.displayTextAndVCCForDocument(cdocFile.toPath().getFileName().toString());
            interactionParams.addAuthListener(e -> System.out.println("Verification code:" + e.getVerificationCode()));
            paramsConfigurable.init(interactionParams);
        }
    }
```


## SSH public key recipients (ssh-agent)

A CDOC2 document can be encrypted to an SSH public key and decrypted with the matching private key held in
`ssh-agent`. Only ECDSA P-256 keys (`ecdsa-sha2-nistp256`) are supported.

The key is split into N-of-N key shares on the shares servers, as for Smart-ID/Mobile-ID. To get the shares,
the recipient signs the auth token with the SSH key through `ssh-agent`, which can sign but can't decrypt.
The recipient identifier is the public key itself, `ruhnu/pk/<base64 OpenSSH public key blob>`. The scheme is
described step by step in
[CDOC2 with symmetric key from/to N-of-N shares (SSH public key, ssh-agent)](../README.md#cdoc2-with-symmetric-key-fromto-n-of-n-shares-ssh-public-key-ssh-agent).
The token is signed once for all shares, so with an `ssh-add -c` key the user confirms only once.

### Encrypting to an SSH public key

```java
// normally initialized through -D option to java process
System.setProperty("key-shares.properties", "config/localhost/key-shares.properties");
Services services = Cdoc2Services.initFromSystemProperties();

EncryptionKeyMaterial sshRecipient = EncryptionKeyMaterial.fromSshPublicKeyFile(
        Path.of(System.getProperty("user.home"), ".ssh", "id_ecdsa.pub"),
        Duration.ofDays(7)); // requested share lifetime, null for shares server default
// or EncryptionKeyMaterial.fromSshPublicKey("ecdsa-sha2-nistp256 AAAAE2Vj... user@host", null)

new CDocBuilder()
        .withPayloadFiles(List.of(payloadFile))
        .withRecipients(List.of(sshRecipient))
        .withServices(services)
        .buildToFile(cdoc2FileToCreate);
```

Unsupported key types (Ed25519, RSA, other ECDSA curves) and malformed keys are rejected with
`InvalidSshPublicKeyException` before anything is uploaded.

### Decrypting with ssh-agent

```java
System.setProperty("key-shares.properties", "config/localhost/key-shares.properties");
Services services = Cdoc2Services.initFromSystemProperties();

// recipient identifier of the key to use, from its OpenSSH public key line
String recipientId = SshPublicKeyParser.recipientIdFromOpenSshLine(
        Files.readString(Path.of(System.getProperty("user.home"), ".ssh", "id_ecdsa.pub")));

List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withServices(services)
        .withRecipient(DecryptionKeyMaterial.fromSshAgentKey(recipientId))
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```

The agent at `$SSH_AUTH_SOCK` is used, unless an `SshAgentClient` is registered in `Services`. The container's
SSH recipients can be listed with `Envelope.parseHeader()`: they are `KeySharesRecipient`s with recipient type
`KeyShareRecipientType.RUHNU`, whose `getRecipientId()` starts with `ruhnu/pk/`.

Agent problems are reported as `SshAgentException` with a `getReason()`: `NO_AUTH_SOCK`, `CONNECTION_FAILED`,
`KEY_NOT_FOUND` or `AGENT_REFUSED` (for example, the user declined an `ssh-add -c` confirmation). A shares server
that no longer has the share (it has expired or was deleted) is reported as `KeyShareAccessException`.


## DID recipients (ssh-agent)

A CDOC2 document can be encrypted to the SSH keys a `did:web` DID document lists for `authentication`
(ECDSA P-256 `publicKeyJwk` keys whose `controller` is the DID). Each key becomes a recipient
`ruhnu/did/<did>/hash/<fingerprint>` (`DidRecipientId`): the fingerprint pins the key in the container, and the
shares servers release a share only while the DID document still lists the key. The scheme is described in
[CDOC2 with symmetric key from/to N-of-N shares (DID, ssh-agent)](../README.md#cdoc2-with-symmetric-key-fromto-n-of-n-shares-did-ssh-agent).

### Encrypting to a DID

Resolve the DID before building the container, so that nothing is uploaded if it can't be used:

```java
DidWebResolver resolver = DidWebResolver.createDefault(
        DidWebResolver.DEFAULT_CONNECT_TIMEOUT, DidWebResolver.DEFAULT_DEADLINE, DidHostPolicy.ALLOW_ALL);
DidRecipients.Resolved resolved = DidRecipients.resolve(
        "did:web:example.org:p:alice",
        Duration.ofDays(30), // requested share lifetime, null for shares server default
        resolver);
// show resolved.keyMaterials() fingerprints (SshDidEncryptionKeyMaterial.openSshFingerprint()) and
// resolved.skipped() to the user: the DID host is trusted at this moment

new CDocBuilder()
        .withPayloadFiles(List.of(payloadFile))
        .withRecipients(new ArrayList<>(resolved.keyMaterials()))
        .withServices(services)
        .buildToFile(cdoc2FileToCreate);
```

`DidRecipients.resolve` throws `DidRecipientException` with a `getReason()`: `INVALID_DID` (not did:web, not a
valid did:web DID, too long), `NOT_FOUND`, `UNAVAILABLE` or `NO_SUPPORTED_KEY`.

### Decrypting a DID recipient with ssh-agent

The recipient identifier holds only the key's fingerprint, so the key material needs the agent key's public
key blob too. The client does not resolve the DID; each shares server does.

```java
String recipientId = "ruhnu/did/did:web:example.org:p:alice/hash/ILaep1_NfsYICEypSkuVoSj0tD6P-nvxnABaRhsg-uc";
byte[] keyBlob = Base64.getDecoder().decode(publicKeyLine.split(" ")[1]); // key in the agent

List<String> extractedFiles = new CDocDecrypter()
        .withCDoc(cdoc2FileToDecrypt.toFile())
        .withServices(services)
        .withRecipient(DecryptionKeyMaterial.fromSshAgentDidKey(recipientId, keyBlob))
        .withDestinationDirectory(destDir.toFile())
        .decrypt();
```

The auth token carries the public key in its JWS `jwk` header. A shares server's refusal is reported as
`KeyShareAccessException`: `isRetryable()` is true when the server could not reach the DID host (HTTP 503), and
false when the share was not found, has expired, or the DID document no longer lists the key (HTTP 404).
Agent problems are reported as `SshAgentException`, as for SSH public key recipients.


## Long-term crypto

Scenarios with id-card are meant for transport cryptography only as id-card certificates expiry and
also cdoc2-capsule-server deletes key material after some time. To store CDOC2 documents for longer time,
it's recommended to re-encrypt CDOC2 documents with a password or symmetric key. When re-encrypting,
then files in CDOC2 container are not written to disk - only parts of CDOC2 are decrypted temporary
into memory. To re-encrypt existing CDOC2 document, use [CDocReEncrypter](cdoc2-lib/src/main/java/ee/cyber/cdoc2/CDocReEncrypter.java) class

For usage see [CDocReEncryptCmd.java](https://github.com/open-eid/cdoc2-java-ref-impl/blob/f91a917fc0fb47f35e9e4f69de4d0108b620d00d/cdoc2-cli/src/main/java/ee/cyber/cdoc2/cli/commands/CDocReEncryptCmd.java) from `cdoc2-cli`

# CDOC sample code

See [cdoc2-example-app](https://github.com/open-eid/cdoc2-java-ref-impl/tree/master/cdoc2-example-app) -
uses both `cdoc4j` and `cdoc2-lib`