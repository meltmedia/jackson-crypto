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
    CryptoModule module = new CryptoModule().withSource(Defaults.DEFAULT_NAME, service);
    version = module.version();
  }

  @Test
  public void shouldNotBeUnknownVersion() {
    assertThat(version.isUknownVersion(), equalTo(false));
  }

  @Test
  public void shouldReturnMajorMinorAndPatch() {
    assertThat(version.getMajorVersion() + version.getMinorVersion() + version.getPatchLevel(),
        greaterThan(0));
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
