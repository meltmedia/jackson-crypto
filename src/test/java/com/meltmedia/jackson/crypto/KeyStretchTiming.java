package com.meltmedia.jackson.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import com.carrotsearch.junitbenchmarks.BenchmarkOptions;
import com.carrotsearch.junitbenchmarks.BenchmarkRule;

/**
 * Provides some timing information for the key stretching algorithm used in the
 * crypto package.  This class is not part of the regular testing suite.
 * 
 * @author Christian Trimble
 *
 */
public class KeyStretchTiming {
  private static Base64 base64 = new Base64();
  char[] password;
  byte[] salt;
  int keyLength;

  @Rule
  public TestRule benchmarkRun = new BenchmarkRule();

  @Before
  public void setUp() {
    salt = base64.decode("Z/t5j0YbTCGstAurhMWzow==");
    password = "password".toCharArray();
    keyLength = 256;
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch10000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 10000, keyLength);
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch20000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 20000, keyLength);
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch40000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 40000, keyLength);
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch80000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 80000, keyLength);
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch160000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 160000, keyLength);
  }

  @Test
  @BenchmarkOptions(callgc = false, benchmarkRounds = 20, warmupRounds = 3)
  public void timeKeyStretch64000() throws NoSuchAlgorithmException, InvalidKeySpecException {
    AbstractEncryptionService.stretchKey(password, salt, 64000, keyLength);
  }

}
