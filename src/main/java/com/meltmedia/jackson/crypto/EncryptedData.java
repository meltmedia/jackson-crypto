package com.meltmedia.jackson.crypto;

import javax.validation.constraints.NotNull;

/**
 * A container type for encrypted data.  Data contained in this type should
 * only be decrypted just before use.
 * 
 * @author Christian Trimble
 *
 */
public class EncryptedData extends EncryptedValue {
  @NotNull
  protected String keyName;

  public String getKeyName() {
    return keyName;
  }

  public void setKeyName( String keyName ) {
    this.keyName = keyName;
  }
}
