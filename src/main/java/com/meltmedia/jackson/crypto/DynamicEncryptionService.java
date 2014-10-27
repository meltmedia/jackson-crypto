package com.meltmedia.jackson.crypto;

/**
 * An encryption service for long lived data.  This service supports multiple keys, so
 * that a key rotation process can be supported.
 * 
 * @author Christian Trimble
 *
 */
public class DynamicEncryptionService extends AbstractEncryptionService<EncryptedJson> {
  public DynamicEncryptionService( DynamicEncryptionConfiguration configuraiton ) {
    this.config = configuraiton;
  }

  protected DynamicEncryptionConfiguration config;

  /**
   * Creates a new encrypted data object with the current cipher set as the objects cipher.
   */
  @Override
  public EncryptedJson newEncrypted() {
    EncryptedJson data = new EncryptedJson();
    data.setKeyName(config.getCurrentKey());
    return data;
  }

  @Override
  public char[] getKey( EncryptedJson encrypted ) {
	  if( !config.getKeys().containsKey(encrypted.getKeyName())) {
		  throw new EncryptionException(String.format("encryption key %s not defined", encrypted.getKeyName()));
	  }
    return config.getKeys().get(encrypted.getKeyName());
  }

}
