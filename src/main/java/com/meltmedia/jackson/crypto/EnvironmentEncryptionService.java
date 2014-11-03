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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.meltmedia.jackson.crypto.EncryptionService.Function;
import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

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
public class EnvironmentEncryptionService {
  private static final Logger logger = LoggerFactory.getLogger(EnvironmentEncryptionService.class);

  public static final int ITERATION_COUNT = 64000;
  public static final int KEY_LENGTH = 256;

  // This value is needed from the deserializer, so it is constructed
  // statically. I haven't
  // found any Jackson documentation on injecting values into deserializers.
  private static EncryptionService<EncryptedJson> cipher;
  static {
    try {
      cipher =
          new EncryptionService.Builder<EncryptedJson>()
              .withEncryptedJsonSupplier(encryptedJsonSupplier())
              .withPassphraseLookup(unitializedPassphraseFunction())
              .withIterations(ITERATION_COUNT).withKeyLength(KEY_LENGTH).build();
    } catch (Exception e) {
      logger.error("could not create configuration cipher", e);
    }
  }

  public static EncryptionService<EncryptedJson> getCipher() {
    return cipher;
  }

  public static EncryptionService<EncryptedJson> init(String envVar) {
    return cipher =
        new EncryptionService.Builder<EncryptedJson>()
            .withEncryptedJsonSupplier(encryptedJsonSupplier())
            .withPassphraseLookup(passphraseFunction(envVar)).withIterations(ITERATION_COUNT)
            .withKeyLength(KEY_LENGTH).build();
  }

  public static Supplier<EncryptedJson> encryptedJsonSupplier() {
    return new Supplier<EncryptedJson>() {
      @Override
      public EncryptedJson get() {
        return new EncryptedJson();
      }
    };
  }

  public static Function<String, char[]> unitializedPassphraseFunction() {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String domain) {
        throw new EncryptionException("environment encryption service not initialized");
      }

    };
  }

  public static Function<String, char[]> passphraseFunction(final String envVar) {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String domain) {
        return System.getenv(envVar).toCharArray();
      }
    };
  }
}
