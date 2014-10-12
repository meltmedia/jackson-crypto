package com.meltmedia.jackson.crypto;

/**
 * Settings for a named cipher.  These allow you to set:
 * 
 * - password: the password for the cipher
 * - iteration count: the number of iterations used when key stretching
 * - key length: the length of the key used.
 * 
 * @author Christian Trimble
 *
 */
public class CipherSettings {
  protected char[] password;
  protected int iterationCount;
  protected int keyLength;

  public char[] getPassword() {
    return password;
  }

  public void setPassword( char[] password ) {
    this.password = password;
  }

  public int getIterationCount() {
    return iterationCount;
  }

  public void setIterationCount( int iterationCount ) {
    this.iterationCount = iterationCount;
  }

  public int getKeyLength() {
    return keyLength;
  }

  public void setKeyLength( int keyLength ) {
    this.keyLength = keyLength;
  }
}