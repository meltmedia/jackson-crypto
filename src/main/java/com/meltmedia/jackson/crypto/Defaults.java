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

import javax.validation.Validation;
import javax.validation.ValidationException;
import javax.validation.Validator;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Defaults {
  public static final String DEFAULT_CIPHER = Ciphers.AES_256_CBC;
  public static final String DEFAULT_KEY_DERIVATION = KeyDerivations.PBKDF2;
  public static final int KEY_LENGTH = 256;
  public static final int KEY_STRETCH_ITERATIONS = 2000;
  public static final int SALT_LENGTH = 4;
  public static final String DEFAULT_NAME = "default";
  public static final String DEFAULT_ENCODING = "UTF-8";

  /**
   * Creates a default validator, if the supplied validator is null.
   */
  public static Validator defaultValidator(Validator validator) {
    if (validator != null)
      return validator;
    try {
      return Validation.buildDefaultValidatorFactory().getValidator();
    } catch (ValidationException ve) {
      throw new RuntimeException("cannot create dafault validator", ve);
    }
  }

  public static ObjectMapper defaultObjectMapper(ObjectMapper mapper) {
    if (mapper != null)
      return mapper;
    return new ObjectMapper();
  }
}
