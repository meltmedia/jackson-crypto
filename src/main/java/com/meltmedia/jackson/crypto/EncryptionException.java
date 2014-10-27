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

  public EncryptionException( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace ) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public EncryptionException( String message, Throwable cause ) {
    super(message, cause);
  }

  public EncryptionException( String message ) {
    super(message);
  }

  public EncryptionException( Throwable cause ) {
    super(cause);
  }

}
