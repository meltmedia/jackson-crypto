package com.meltmedia.jackson.crypto;

import java.util.LinkedHashMap;
import java.util.Map;

import com.meltmedia.jackson.crypto.EncryptionService.Function;
import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

/**
 * A configuration block for the DataEncryptionService.  This block should
 * be encrypted on disk and decrypted as it is read into memory.
 * 
 * @author Christian Trimble
 *
 */
public class DynamicEncryptionConfiguration {
  protected String currentKey;
  protected Map<String, char[]> keys = new LinkedHashMap<>();

  public String getCurrentKey() {
    return currentKey;
  }

  public void setCurrentKey(String currentCipher) {
    this.currentKey = currentCipher;
  }

  public Map<String, char[]> getKeys() {
    return keys;
  }

  public void setKeys(Map<String, char[]> keys) {
    this.keys = keys;
  }

  public Supplier<EncryptedJson> encryptedJsonSupplier() {
    return new Supplier<EncryptedJson>() {

      @Override
      public EncryptedJson get() {
        EncryptedJson data = new EncryptedJson();
        data.setKeyName(currentKey);
        return data;
      }
    };
  }

  public Function<String, char[]> passphraseFunction() {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String keyName) {
        if (!keys.containsKey(keyName)) {
          throw new EncryptionException(String.format("encryption key %s not defined", keyName));
        }
        return keys.get(keyName);

      }

    };
  }
}
