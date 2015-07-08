package com.meltmedia.jackson.crypto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.fail;

import java.util.HashMap;

import org.junit.Test;

import com.meltmedia.jackson.crypto.EncryptionService.Function;

public class FunctionsTest {
  @Test
  public void shouldThrowWhenPasswordEnvVarNotDefined() {
    String envVar = "NOT_DEFINED_ENV_VARIABLE";
    Function<String, char[]> passphraseFunction = Functions.passphraseFunction(envVar);
    
    try {
      passphraseFunction.apply(null);
      
      fail("exception not thrown for missing environment variable");
    }
    catch( EncryptionException e ) {
      assertThat(e.getMessage().contains(envVar), equalTo(true));
      assertThat(e.getMessage().contains("not defined"), equalTo(true));
    }
  }
  
  @Test
  public void shouldThrowWhenKeyNameProvidedForEnvVarPassphrase() {
    String envVar = "NOT_DEFINED_ENV_VARIABLE";
    Function<String, char[]> passphraseFunction = Functions.passphraseFunction(envVar);
    
    try {
      passphraseFunction.apply("name");
      
      fail("exception not thrown when key name provided for environment variable");
    }
    catch( EncryptionException e ) {
      assertThat(e.getMessage().contains("named keys"), equalTo(true));
    }    
  }
  
  @Test
  public void shouldThrowWhenKeyNameProvidedForConstPassphrase() {
    Function<String, char[]> passphraseFunction = Functions.constPassphraseFunction("constant");
    
    try {
      passphraseFunction.apply("name");
      
      fail("exception not thrown when key name provided for constant passphrase");
    }
    catch( EncryptionException e ) {
      assertThat(e.getMessage().contains("named keys"), equalTo(true));
    }    
  }
  
  @Test
  public void shouldProvideConstantPassphrase() {
    String passphrase = "constant";
    Function<String, char[]> passphraseFunction = Functions.constPassphraseFunction(passphrase);
    
    assertThat(passphraseFunction.apply(null), equalTo(passphrase.toCharArray()));   
  }

  @Test
  public void shouldThrowWhenKeyNotDefined() {
    Function<String, char[]> passphraseFunction = Functions.passphraseFunction(new HashMap<String, char[]>());
    String key = "theKey";
    try {
      passphraseFunction.apply(key);
      
      fail("exception not thrown when key not defined");
    }
    catch( EncryptionException e ) {
      assertThat(e.getMessage().contains(key), equalTo(true));
      assertThat(e.getMessage().contains("not defined"), equalTo(true));
    }    
  }

  @Test
  public void shouldThrowWhenKeyNameNotDefined() {
    Function<String, char[]> passphraseFunction = Functions.passphraseFunction(new HashMap<String, char[]>());
    String key = null;
    try {
      passphraseFunction.apply(key);
      
      fail("exception not thrown when key name is not defined");
    }
    catch( EncryptionException e ) {
      assertThat(e.getMessage().contains("key name"), equalTo(true));
      assertThat(e.getMessage().contains("not defined"), equalTo(true));
    }    
  }}
