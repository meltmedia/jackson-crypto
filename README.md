# Jackson Crypto

[![Build Status](https://travis-ci.org/meltmedia/jackson-crypto.svg?branch=develop)](https://travis-ci.org/meltmedia/jackson-crypto)

Cryptographic utilities for Jackson.

## Usage

To use this package from Maven, include the following dependency in your project:

```
<dependency>
  <groupId>com.meltmedia.jackson</groupId>
  <artifactId>jackson-crypto</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dpendency>
```

Then create a new CryptoModule and register it with your ObjectMapper.

```
EncryptionService service = ...;
ObjectMapper mapper = ...;
mapper.registerModule(new CryptoModule(service));
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
    "salt": ""
    "iv": ""
    "value": ""
    "cipher": "aes-256-cbc"
    "keyDerivation": "pbkdf2"
    "keyLength": 256
    "iterations": 2000
    "encrypted": true
  }
}
```
