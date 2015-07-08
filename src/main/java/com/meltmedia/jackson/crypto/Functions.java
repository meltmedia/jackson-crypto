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
import static java.lang.String.format;

/**
 * @author Christian Trimble
 *
 */
public class Functions {

  public static Function<String, char[]> passphraseFunction(final String envVar) {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String keyName) {
        if (keyName != null) {
          throw new EncryptionException("envvar passphrase does not support named keys");
        }
        
        String envVarValue = System.getenv(envVar);
        
        if( envVarValue == null ) {
          throw new EncryptionException(format("passphrase environment variable %s is not defined", envVar));
        }

        return envVarValue.toCharArray();
      }
    };
  }

  public static Function<String, char[]> constPassphraseFunction(final String passphrase) {
    return new Function<String, char[]>() {
      @Override
      public char[] apply(String keyName) {
        if (keyName != null) {
          throw new EncryptionException("const passphrase does not support named keys");
        }
        return passphrase.toCharArray();
      }
    };
  }

  public static Function<String, char[]> passphraseFunction(final Map<String, char[]> keys) {
    return new Function<String, char[]>() {
      @Override
      public char[] apply(String keyName) {
        if (keyName == null) {
          throw new EncryptionException("key name not defined");
        }
        
        char[] key = keys.get(keyName);
        if (key == null)
          throw new EncryptionException(String.format("key %s is not defined", keyName));
        return key;
      }
    };
  }
}
