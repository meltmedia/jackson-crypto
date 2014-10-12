package com.meltmedia.jackson.crypto;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * A base type for encrypted values.
 * 
 * @author Christian Trimble
 *
 */
public abstract class EncryptedValue {
  @NotNull
  protected byte[] salt;
  @NotNull
  protected byte[] iv;
  @NotNull
  protected byte[] value;
  @NotNull
  private EncryptedValue.Cipher cipher;
  @NotNull
  private EncryptedValue.KeyDerivation keyDerivation;
  @Min(1)
  private int keyLength;
  @Min(1)
  private int iterations;
  private boolean encrypted;
  @JsonIgnore
  private Map<String, Object> additionalProperties = new LinkedHashMap<String, Object>();

  public byte[] getSalt() {
    return salt;
  }

  public void setSalt( byte[] salt ) {
    this.salt = salt;
  }

  public byte[] getIv() {
    return iv;
  }

  public void setIv( byte[] iv ) {
    this.iv = iv;
  }

  public byte[] getValue() {
    return value;
  }

  public void setValue( byte[] value ) {
    this.value = value;
  }
  

  public EncryptedValue.Cipher getCipher() {
    return cipher;
  }

  public void setCipher( EncryptedValue.Cipher cipher ) {
    this.cipher = cipher;
  }

  public EncryptedValue.KeyDerivation getKeyDerivation() {
    return keyDerivation;
  }

  public void setKeyDerivation( EncryptedValue.KeyDerivation keyDerivation ) {
    this.keyDerivation = keyDerivation;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public void setKeyLength( int keyLength ) {
    this.keyLength = keyLength;
  }

  public int getIterations() {
    return iterations;
  }

  public void setIterations( int iterations ) {
    this.iterations = iterations;
  }

  public boolean isEncrypted() {
    return encrypted;
  }

  public void setEncrypted( boolean encrypted ) {
    this.encrypted = encrypted;
  }
  
  @JsonAnySetter
  public void setAdditionalProperty( String key, Object value ) {
    additionalProperties.put(key, value);
  }

  @JsonAnyGetter
  public Map<String, Object> getAdditionalProperties() {
    return additionalProperties;
  }
  
  public static enum Cipher {

    AES_256_CBC("aes-256-cbc");
    private final String value;
    private static Map<String, EncryptedValue.Cipher> constants = new HashMap<String, EncryptedValue.Cipher>();

    static {
        for (EncryptedValue.Cipher c: EncryptedValue.Cipher.values()) {
            constants.put(c.value, c);
        }
    }

    private Cipher(String value) {
        this.value = value;
    }

    @JsonValue
    @Override
    public String toString() {
        return this.value;
    }

    @JsonCreator
    public static EncryptedValue.Cipher fromValue(String value) {
        EncryptedValue.Cipher constant = constants.get(value);
        if (constant == null) {
            throw new IllegalArgumentException(value);
        } else {
            return constant;
        }
    }

}

public static enum KeyDerivation {

    PBKDF_2("pbkdf2");
    private final String value;
    private static Map<String, EncryptedValue.KeyDerivation> constants = new HashMap<String, EncryptedValue.KeyDerivation>();

    static {
        for (EncryptedValue.KeyDerivation c: EncryptedValue.KeyDerivation.values()) {
            constants.put(c.value, c);
        }
    }

    private KeyDerivation(String value) {
        this.value = value;
    }

    @JsonValue
    @Override
    public String toString() {
        return this.value;
    }

    @JsonCreator
    public static EncryptedValue.KeyDerivation fromValue(String value) {
        EncryptedValue.KeyDerivation constant = constants.get(value);
        if (constant == null) {
            throw new IllegalArgumentException(value);
        } else {
            return constant;
        }
    }

}

}
