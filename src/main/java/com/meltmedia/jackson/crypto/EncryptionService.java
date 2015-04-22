/**
 * Copyright (C) 2014 meltmedia (christian.trimble@meltmedia.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.meltmedia.jackson.crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.ConstraintViolation;
import javax.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * A base class for encryption service implementations.
 * 
 * ## Keys
 * 
 * The keys in this implementation are created using PBKDF2WithHmacSHA1 key stretching.  Options for the stretch iterations and key length
 * can be specified.
 *   
 * ## Cipher
 * 
 * The ciphers used by this implementation are created using AES/CBC/PKCS5Padding.
 *   
 * ## General Settings
 * 
 * - AES 256
 * - CBC mode with 128 bit blocks
 * - PBKDF2 w/ a configurable stretch iterations
 * - 32 bit salt
 * 
 * 
 * @author Christian Trimble
 *
 */
public class EncryptionService {
  private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

  /**
   * Remove cryptographic restrictions in the JVM.
   */
  static {
    try {
      Field field = Class.forName("javax.crypto.JceSecurity").getDeclaredField("isRestricted");
      field.setAccessible(true);
      field.set(null, java.lang.Boolean.FALSE);
    } catch (ClassNotFoundException | NoSuchFieldException | SecurityException
        | IllegalArgumentException | IllegalAccessException ex) {
      logger.info("cannot remove JCE Security restrictions", ex);
    }
  }

  public static class Builder {
    ObjectMapper mapper;
    Validator validator;
    Function<String, char[]> passphraseLookup;
    Supplier<byte[]> saltSupplier;
    int iterations = Defaults.KEY_STRETCH_ITERATIONS;
    int keyLength = Defaults.KEY_LENGTH;
    String name = Defaults.DEFAULT_NAME;
    String currentKeyName;

    public Builder withObjectMapper(ObjectMapper mapper) {
      this.mapper = mapper;
      return this;
    }

    public Builder withValidator(Validator validator) {
      this.validator = validator;
      return this;
    }
    
    public Builder withCurrentKeyName( String currentKeyName ) {
      this.currentKeyName = currentKeyName;
      return this;
    }

    public Builder withPassphraseLookup(Function<String, char[]> passphraseLookup) {
      this.passphraseLookup = passphraseLookup;
      return this;
    }

    public Builder withSaltSupplier(Supplier<byte[]> saltSupplier) {
      this.saltSupplier = saltSupplier;
      return this;
    }

    public Builder withIterations(int iterations) {
      this.iterations = iterations;
      return this;
    }

    public Builder withKeyLength(int keyLength) {
      this.keyLength = keyLength;
      return this;
    }

    public Builder withName(String name) {
      this.name = name;
      return this;
    }

    public EncryptionService build() {
      Supplier<byte[]> buildSaltSupplier =
          saltSupplier != null ? saltSupplier : Salts.saltSupplier();
      if (passphraseLookup == null) {
        throw new IllegalArgumentException("the key lookup function is required.");
      }
      return new EncryptionService(name, Defaults.defaultObjectMapper(mapper),
          Defaults.defaultValidator(validator), currentKeyName, buildSaltSupplier,
          passphraseLookup, iterations, keyLength);
    }

  }

  public static interface Supplier<T> {
    public T get();
  }

  public static interface Function<D, R> {
    public R apply(D domain);
  }

  public static Builder builder() {
    return new Builder();
  }

  Supplier<byte[]> saltSupplier;
  Function<String, char[]> passphraseLookup;
  ObjectMapper mapper;
  Validator validator;
  int iterations;
  int keyLength;
  String name;
  String currentKeyName;

  public EncryptionService(String name, ObjectMapper mapper, Validator validator,
      String currentKeyName, Supplier<byte[]> saltSupplier,
      Function<String, char[]> passphraseLookup, int iterations, int keyLength) {
    this.name = name;
    this.mapper = mapper;
    this.validator = validator;
    this.passphraseLookup = passphraseLookup;
    this.saltSupplier = saltSupplier;
    this.iterations = iterations;
    this.keyLength = keyLength;
    this.currentKeyName = currentKeyName;
  }

  private void validate(EncryptedJson encrypted) throws EncryptionException {
    if (encrypted == null) {
      throw new EncryptionException("null encrypted value encountered");
    }

    Set<ConstraintViolation<EncryptedJson>> violations = validator.validate(encrypted);

    if (!violations.isEmpty()) {
      String message =
          String.format("invalid encrypted value%n%s",
              validationErrorMessage(encrypted, violations));
      logger.warn(message);
      throw new EncryptionException(message);
    }
  }

  private String validationErrorMessage(EncryptedJson encrypted, Set<ConstraintViolation<EncryptedJson>> violations) {
    StringBuilder sb = new StringBuilder();
    try {
      sb.append("value:").append(mapper.writeValueAsString(encrypted)).append("\n");
    } catch (JsonProcessingException e) {
      sb.append(e.getMessage()).append("\n");
    }
    sb.append("violations:\n");
    for (ConstraintViolation<EncryptedJson> violation : violations) {
      sb.append("- ").append(violation.getPropertyPath().toString() + " " + violation.getMessage())
          .append("\n");
    }
    return sb.toString();
  }

  /**
   * Creates secret key for the encrypted value.  
   * 
   * @param encrypted the encrypted value to create the key for.  The keyName and salt must already be defined.
   * @return the secret key appropriate for the specified value
   * @throws EncryptionException
   */
  SecretKey createSecretKey(EncryptedJson encrypted) throws EncryptionException {
    if (KeyDerivations.PBKDF2.equals(encrypted.getKeyDerivation())) {
      char[] passphrase = passphraseLookup.apply(encrypted.getKeyName());
      try {
        return stretchKey(passphrase, encrypted.getSalt(), encrypted.getIterations(),
            encrypted.getKeyLength());
      } catch (Exception e) {
        throw new EncryptionException("could not generate secret key", e);
      }
    } else {
      throw new EncryptionException(String.format(
          "could not create secret key. unknown key derivation %s", encrypted.getKeyDerivation()));
    }
  }

  /**
   * Performs PBKDF2WithHmacSHA1 key stretching on password and returns a key of the specified length.
   * 
   * @param password the clear text password to base the key on.
   * @param salt the salt to add to the password
   * @param iterationCount the number of iterations used when stretching
   * @param keyLength the length of the resulting key in bits
   * @return the stretched key
   * @throws NoSuchAlgorithmException if PBKDF2WithHmacSHA1 is not available
   * @throws InvalidKeySpecException if the specification of the key is invalid.
   */
  static SecretKey stretchKey(char[] password, byte[] salt, int iterationCount, int keyLength)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    KeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLength);
    return factory.generateSecret(spec);
  }

  /**
   * Creates a cipher for doing encryption.  The generated iv is placed in the value as a side effect.
   * 
   * @param secret the pre stretched secret key
   * @param value the value that the encrypted data will be stored in.
   * @return the cipher to use.
   * @throws EncryptionException
   */
  Cipher createEncryptionCipher(SecretKey secret, EncryptedJson value) throws EncryptionException {
    if (Ciphers.AES_256_CBC.equals(value.getCipher())
        && KeyDerivations.PBKDF2.equals(value.getKeyDerivation())) {
      try {
        SecretKeySpec spec = new SecretKeySpec(secret.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        AlgorithmParameters params = cipher.getParameters();
        value.setIv(params.getParameterSpec(IvParameterSpec.class).getIV());
        return cipher;
      } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
          | InvalidParameterSpecException e) {
        throw new EncryptionException("could not create encryption cypher", e);
      }
    } else {
      throw new EncryptionException(String.format("unsupported cipher %s and key derivation %s",
          value.getCipher(), value.getKeyDerivation()));
    }
  }

  /**
   * Creates a decryption cipher for the encrypted value value using `AES/CBC/PKCS5Padding`.  The base64 encoded
   * iv must already be present in the encrypted value.
   * 
   * @param secret the key to use for decryption.
   * @param value the value that will decrypted with this cipher.  The base64 iv must be present on this value.
   * @return a cipher that will decrypt the specified value with the specified key.
   * @throws EncryptionException if the cipher could not be created for any reason.
   */
  Cipher createDecryptionCipher(SecretKey secret, EncryptedJson value) throws EncryptionException {
    if (Ciphers.AES_256_CBC.equals(value.getCipher())
        && KeyDerivations.PBKDF2.equals(value.getKeyDerivation())) {
      try {
        SecretKeySpec spec = new SecretKeySpec(secret.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, spec, new IvParameterSpec(value.getIv()));
        return cipher;
      } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
          | InvalidAlgorithmParameterException e) {
        throw new EncryptionException("could not create decryption cypher", e);
      }
    } else {
      throw new EncryptionException(String.format("unsupported cipher %s and key derivation %s",
          value.getCipher(), value.getKeyDerivation()));
    }
  }

  /**
   * Encrypts the given data and returns an encrypted value for it.
   * 
   * @param data the data to encrypt
   * @return the encrypted value, along with the salt, iv, and name of the settings used.
   * @throws EncryptionException if the value could not be encrypted for any reason.
   */
  public EncryptedJson encrypt(byte[] data) throws EncryptionException {
    EncryptedJson result = new EncryptedJson();
    result.setKeyName(currentKeyName);
    result.setSalt(saltSupplier.get());
    result.setCipher(Defaults.DEFAULT_CIPHER);
    result.setKeyDerivation(Defaults.DEFAULT_KEY_DERIVATION);
    result.setKeyLength(keyLength);
    result.setIterations(iterations);

    SecretKey secret = createSecretKey(result);
    Cipher cipher = createEncryptionCipher(secret, result);

    try {
      byte[] encrypted = cipher.doFinal(data);
      result.setValue(encrypted);
      return result;
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new EncryptionException("could not encrypt text", e);
    }
  }
  
  public <E> E encrypt(byte[] data, Class<E> encryptedType) throws EncryptionException {
    return mapper.convertValue(encrypt(data), encryptedType);
  }

  /**
   * Encrypts the given text using the specified encoding.
   * 
   * @param text the text to encrypt.
   * @param encoding the encoding to use.
   * @return the encrypted value, along with the salt, iv, and other properties required for decryption.
   * 
   * @throws UnsupportedEncodingException if the encoding is unsupported.
   * @throws EncryptionException if the value could not be encrypted for any reason.
   */
  public EncryptedJson encrypt(String text, String encoding) throws UnsupportedEncodingException,
      EncryptionException {
    return encrypt(text.getBytes(encoding));
  }

  public <E> E encrypt(String text, String encoding, Class<E> encryptedType) throws UnsupportedEncodingException,
      EncryptionException {
    return mapper.convertValue(encryptValue(text, encoding), encryptedType);
  }

  public <T> EncryptedJson encryptValue(T node, String encoding) throws UnsupportedEncodingException,
      EncryptionException {
    try {
      return encrypt(mapper.writeValueAsString(node), encoding);
    } catch (JsonProcessingException e) {
      throw new EncryptionException("could not serialize node", e);
    }
  }
  
  public <T, E> E encryptValue(T node, String encoding, Class<E> encryptedType ) throws UnsupportedEncodingException,
    EncryptionException {
    return mapper.convertValue(encryptValue(node, encoding), encryptedType);
  }

  /**
   * Decrypts the encrypted value.
   * 
   * @param value the value to decrypt.
   * @return the decrypted value.
   * @throws EncryptionException if the value could not be decypted for any reason.
   */
  public byte[] decrypt(EncryptedJson value) throws EncryptionException {
    // make sure the value is valid.
    validate(value);

    SecretKey secret = createSecretKey(value);
    Cipher cipher = createDecryptionCipher(secret, value);
    try {
      return cipher.doFinal(value.getValue());
    } catch (IllegalBlockSizeException | BadPaddingException e) {
      throw new EncryptionException("could not decrypt text", e);
    }
  }

  public <E> byte[] decypt(E value) throws EncryptionException {
    return decrypt(mapper.convertValue(value, EncryptedJson.class));
  }

  /**
   * Decrypts the encrypted value into a string, using the specified encoding.
   * 
   * @param value the value to decrypt.
   * @param encoding the encoding used to convert the value into a string.
   * @return the decrypted string.
   * @throws UnsupportedEncodingException if the encoding is not supported.
   * @throws EncryptionException if the value could not be decrypted for any reason.
   */
  public String decrypt(EncryptedJson value, String encoding) throws UnsupportedEncodingException,
      EncryptionException {
    return new String(decrypt(value), encoding);
  }

  public <E> String decrypt(E value, String encoding) throws UnsupportedEncodingException,
      EncryptionException {
    return decrypt(mapper.convertValue(value, EncryptedJson.class), encoding);
  }
  
  public JsonParser decrypt(JsonParser parser, String encoding) throws JsonParseException,
      JsonMappingException, UnsupportedEncodingException, EncryptionException, IOException {
    try {
      return mapper.getFactory().createParser(
          decrypt(mapper.readValue(parser, EncryptedJson.class), encoding));
    } catch (EncryptionException ee) {
      throw ee;
    } catch (Exception e) {
      throw new EncryptionException("could not decrypt from parser", e);
    }
  }


  public <T> T decryptAs(EncryptedJson secret, String encoding, Class<T> type) throws EncryptionException {
    try {
      return mapper.readValue(decrypt(secret, encoding), type);
    } catch (IOException e) {
      throw new EncryptionException("could not decrypt value", e);
    }
  }
  
  public <T, E> T decryptAs(E secret, String encoding, Class<T> type) throws EncryptionException {
    return decryptAs(mapper.convertValue(secret, EncryptedJson.class), encoding, type);
  }

  public String getName() {
    return name;
  }

  public Object decrypt(JsonParser parser, JsonDeserializer<?> deser,
      DeserializationContext context, JavaType type) {
    try {
      if (deser == null) {
        return mapper.readValue(decrypt(mapper.readValue(parser, EncryptedJson.class)), type);
      } else {
        return deser.deserialize(
            mapper.getFactory().createParser(
                decrypt(mapper.readValue(parser, EncryptedJson.class))), context);
      }
    } catch (EncryptionException ee) {
      throw ee;
    } catch (Exception e) {
      throw new EncryptionException("could not decyrpt value", e);
    }

  }
}
