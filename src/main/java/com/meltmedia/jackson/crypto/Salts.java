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

import java.security.SecureRandom;
import java.util.Random;

import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

/**
 * Static methods for creating salt suppliers.
 * 
 * @author Christian Trimble
 */
public class Salts {
  private static final Random defaultRandom = new SecureRandom();

  /**
   * Constructs a new salt supplier with the specified random and salt length.
   * 
   * @param random the source of randomness for the generated salts.
   * @param length the length of the salts generated.
   * @return a new salt supplier.
   */
  public static Supplier<byte[]> saltSupplier(final Random random, final int length) {
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
    return saltSupplier(defaultRandom, Defaults.SALT_LENGTH);
  }
  
  public static Supplier<byte[]> saltSupplier( final int length ) {
    return saltSupplier(defaultRandom, length);
  }
}
