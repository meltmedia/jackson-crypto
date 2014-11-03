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

import java.util.LinkedHashMap;
import java.util.Map;

import com.meltmedia.jackson.crypto.EncryptionService.Function;
import com.meltmedia.jackson.crypto.EncryptionService.Supplier;

/**
 * A configuration block for the DataEncryptionService.  This block should
 * be encrypted on disk and decrypted as it is read into memory.
 * 
 * @author Christian Trimble
 *
 */
public class DynamicEncryptionConfiguration {
  protected String currentKey;
  protected Map<String, char[]> keys = new LinkedHashMap<>();

  public String getCurrentKey() {
    return currentKey;
  }

  public void setCurrentKey(String currentCipher) {
    this.currentKey = currentCipher;
  }

  public Map<String, char[]> getKeys() {
    return keys;
  }

  public void setKeys(Map<String, char[]> keys) {
    this.keys = keys;
  }

  public Supplier<EncryptedJson> encryptedJsonSupplier() {
    return new Supplier<EncryptedJson>() {

      @Override
      public EncryptedJson get() {
        EncryptedJson data = new EncryptedJson();
        data.setKeyName(currentKey);
        return data;
      }
    };
  }

  public Function<String, char[]> passphraseFunction() {
    return new Function<String, char[]>() {

      @Override
      public char[] apply(String keyName) {
        if (!keys.containsKey(keyName)) {
          throw new EncryptionException(String.format("encryption key %s not defined", keyName));
        }
        return keys.get(keyName);

      }

    };
  }
}
