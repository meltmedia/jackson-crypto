package com.meltmedia.jackson.crypto;

import java.security.SecureRandom;
import java.util.Random;

import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

/**
 * Static methods for creating salt suppliers.
 * 
 * @author Christian Trimble
 */
public class Salts {
	  private static final Random random = new SecureRandom();
	  public static int SALT_BYTE_LENGTH = 4;
	  
	  /**
	   * Constructs a new salt supplier with the specified random and salt length.
	   * 
	   * @param random the source of randomness for the generated salts.
	   * @param length the length of the salts generated.
	   * @return a new salt supplier.
	   */
	  public static Supplier<byte[]> saltSupplier( final Random random, final int length ) {
		  return new Supplier<byte[]>() {
			@Override
			public byte[] get() {
			    byte[] salt = new byte[length];
			    random.nextBytes(salt);
			    return salt;
			} 
		  };
	  }
	  
	  /**
	   * Creates a salt supplier with an internal secure random and
	   * a salt length of SALT_BYTE_LENGTH.
	   * 
	   * @return the default salt supplier.
	   */
	  public static Supplier<byte[]> saltSupplier() {
		  return saltSupplier(random, SALT_BYTE_LENGTH);
	  }
}
