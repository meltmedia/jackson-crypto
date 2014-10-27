package com.meltmedia.jackson.crypto;

import java.util.LinkedHashMap;
import java.util.Map;

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

  public void setCurrentKey( String currentCipher ) {
    this.currentKey = currentCipher;
  }

  public Map<String, char[]> getKeys() {
    return keys;
  }

  public void setKeys( Map<String, char[]> keys ) {
    this.keys = keys;
  }
}
