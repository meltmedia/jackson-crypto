package com.meltmedia.jackson.crypto;

/**
 * An encryption service for long lived data.  This service supports multiple keys, so
 * that a key rotation process can be supported.
 * 
 * @author Christian Trimble
 *
 */
public class DataEncryptionService extends AbstractEncryptionService<EncryptedData> {
  public DataEncryptionService( DataEncryptionConfiguration configuraiton ) {
    this.config = configuraiton;
  }

  protected DataEncryptionConfiguration config;

  /**
   * Creates a new encrypted data object with the current cipher set as the objects cipher.
   */
  @Override
  public EncryptedData newEncrypted() {
    EncryptedData data = new EncryptedData();
    data.setKeyName(config.getCurrentKey());
    return data;
  }

  @Override
  public char[] getKey( EncryptedData encrypted ) {
    return config.getKeys().get(encrypted.getKeyName());
  }

}
