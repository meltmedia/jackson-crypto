package com.meltmedia.jackson.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An encryption service for configuration files.  This service must be statically initialized
 * before being used.
 * 
 * ```
 *   EnvironmentEncryptionService.init(ENV_VAR);
 * ```
 * 
 * @author Christian Trimble
 *
 */
public class EnvironmentEncryptionService extends AbstractEncryptionService<EncryptedJson> {
  private static final Logger logger = LoggerFactory.getLogger(EnvironmentEncryptionService.class);

  public static final int ITERATION_COUNT = 64000;
  public static final int KEY_LENGTH = 256;
  
  // This value is needed from the deserializer, so it is constructed statically.  I haven't
  // found any Jackson documentation on injecting values into deserializers.
  private static EnvironmentEncryptionService cipher;
  static {
    try {
      cipher = new EnvironmentEncryptionService(null);
    } catch( Exception e ) {
      logger.error("could not create configuration cipher", e);
    }
  }
  
  public static EnvironmentEncryptionService init( String envVar ) {
	  return cipher = new EnvironmentEncryptionService(System.getenv(envVar).toCharArray());
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
	  if( password == null ) {
		  throw new EncryptionException("environment encryption service not initialized");
	  }
    return password;
  }
}
