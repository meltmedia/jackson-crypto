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

/**
 * Represents an exception that caused a cryptographic operation to fail.
 * 
 * @author Christian Trimble
 *
 */
public class EncryptionException extends RuntimeException {

  private static final long serialVersionUID = 7704571379074325114L;

  public EncryptionException() {
    super();
  }

  public EncryptionException(String message, Throwable cause, boolean enableSuppression,
      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public EncryptionException(String message, Throwable cause) {
    super(message, cause);
  }

  public EncryptionException(String message) {
    super(message);
  }

  public EncryptionException(Throwable cause) {
    super(cause);
  }

}
