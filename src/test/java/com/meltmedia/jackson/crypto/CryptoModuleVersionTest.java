package com.meltmedia.jackson.crypto;

import static org.mockito.Mockito.*;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.*;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.Version;

public class CryptoModuleVersionTest {
  Version version;
  
  @Before
  public void setUp() {
    @SuppressWarnings("unchecked")
    EncryptionService<EncryptedJson> service = mock(EncryptionService.class);
    CryptoModule module = new CryptoModule(service);
    version = module.version();
  }
  
  @Test
  public void shouldNotBeUnknownVersion() {
    assertThat(version.isUknownVersion(), equalTo(false));
  }
  
  @Test
  public void shouldReturnMajorMinorAndPatch() {
    assertThat(version.getMajorVersion()+version.getMinorVersion()+version.getPatchLevel(), greaterThan(0));
  }
  
  @Test
  public void shouldReturnCorrectArtifactId() {
    assertThat(version.getArtifactId(), equalTo("jackson-crypto"));
  }
  
  @Test
  public void shouldReturnCorrectGroupId() {
    assertThat(version.getGroupId(), equalTo("com.meltmedia.jackson"));
  }
}
