package com.meltmedia.jackson.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An encryption service for configuration files.  The password for this service is loaded
 * from an environment variable called `TALU_PASSWORD`.
 * 
 * @author Christian Trimble
 *
 */
public class EnvironmentEncryptionService extends AbstractEncryptionService<EncryptedJson> {
  private static final Logger logger = LoggerFactory.getLogger(EnvironmentEncryptionService.class);

  public static final String PASSWORD_ENV_VAR = "PASSPHRASE";
  public static final int ITERATION_COUNT = 64000;
  public static final int KEY_LENGTH = 256;
  
  // This value is needed from the deserializer, so it is constructed statically.  I haven't
  // found any Jackson documentation on injecting values into deserializers.
  private static EnvironmentEncryptionService cipher;
  static {
    try {
      cipher = new EnvironmentEncryptionService(System.getenv(PASSWORD_ENV_VAR).toCharArray());
    } catch( Exception e ) {
      logger.error("could not create configuration cipher", e);
    }
  }

  private char[] password;

  public EnvironmentEncryptionService( char[] password ) {
    this.password = password;
  }

  public static EnvironmentEncryptionService getCipher() {
    return cipher;
  }
  
  @Override
  public EncryptedJson newEncrypted() {
    return new EncryptedJson();
  }

  @Override
  public char[] getKey( EncryptedJson encrypted ) {
    return password;
  }
}
