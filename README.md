# Jackson Crypto

[![Build Status](https://travis-ci.org/meltmedia/jackson-crypto.svg?branch=develop)](https://travis-ci.org/meltmedia/jackson-crypto)

Cryptographic utilities for Jackson.

## Usage

To use this package from Maven, include the following dependency in your project:

```
<dependency>
  <groupId>com.meltmedia.jackson</groupId>
  <artifactId>jackson-crypto</artifactId>
  <version>0.2.0</version>
</dpendency>
```

Then create a new CryptoModule and register it with your ObjectMapper.

```
EncryptionService service = ...;
ObjectMapper mapper = ...;
mapper.registerModule(new CryptoModule().addSource(service));
```

Once this is done, you can use the `@Encrypted` annotation on your `@JsonProperty` annotated methods to encrypt them during serialization and
decrypt them during deserialization.  So, a POJO like the following:

```
public class Pojo {
  protected String secret;

  @JsonProperty
  @Encrypted
  public String getSecret() {
    return this.secret;
  }

  public void setSecret( String secret ) {
    this.secret = secret;
  }
}
```

will serialize into JSON like:

```
{
  "secret": {
    "salt": "tKD8wQ==",
    "iv": "s9hTJRaZn6fxxpA4nVfDag==",
    "value": "UZENJOltf+9EZS03AXbmeg==",
    "cipher": "aes-256-cbc",
    "keyDerivation": "pbkdf2",
    "keyLength": 256,
    "iterations": 2000
  }
}
```

## Example

This project does not yet have its own example project, but you can see an example of using this library in the [Dropwizard Crypto example project](https://github.com/meltmedia/dropwizard-crypto/tree/develop/example).
