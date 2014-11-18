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

import java.util.Map;

import com.meltmedia.jackson.crypto.EncryptionService.Function;
import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

/**
 * @author Christian Trimble
 *
 */
public class Functions {

  public static Supplier<EncryptedJson> encryptedJsonSupplier() {
    return new Supplier<EncryptedJson>() {
      @Override
      public EncryptedJson get() {
        return new EncryptedJson();
      }
    };
  }
  
  public static Supplier<EncryptedJson> encryptedJsonSupplier(final String keyName) {
    return new Supplier<EncryptedJson>() {
      @Override
      public EncryptedJson get() {
        return new EncryptedJson().withKeyName(keyName);
      }
    };
  }

  public static Function<String, char[]> passphraseFunction(final String envVar) {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String domain) {
        char[] key = System.getenv(envVar).toCharArray();
        if( key == null ) throw new EncryptionException(String.format("No key defined in environment variable %s", domain));
        return key;
      }
    };
  }
  
  public static Function<String, char[]> passphraseFunction(final Map<String, char[]> keys) {
    return new Function<String, char[]>() {
      @Override
      public char[] apply(String domain) {
        char[] key = keys.get(domain);
        if( key == null ) throw new EncryptionException(String.format("No key defined for name %s", domain));
        return key;
      }
    };    
  }
}
