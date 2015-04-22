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

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.Module;

public class CryptoModule extends Module {

  EncryptedJsonSerializer.Modifier serModifier;
  EncryptedJsonDeserializer.Modifier deserModifier;

  public CryptoModule() {
    this.serModifier = new EncryptedJsonSerializer.Modifier();
    this.deserModifier = new EncryptedJsonDeserializer.Modifier();
  }

  @Override
  public String getModuleName() {
    return "JacksonCrypto";
  }

  @Override
  public void setupModule(SetupContext context) {
    context.addBeanSerializerModifier(serModifier);
    context.addBeanDeserializerModifier(deserModifier);
  }

  public CryptoModule addSource(EncryptionService service) {
    this.serModifier.addSource(service);
    this.deserModifier.addSource(service);
    return this;
  }

  @Override
  public Version version() {
    String[] versionInfo = MavenProperties.VERSION.split("[\\.-]", 4);
    if (versionInfo.length < 3) {
      return Version.unknownVersion();
    }
    try {
      int major = Integer.valueOf(versionInfo[0]);
      int minor = Integer.valueOf(versionInfo[1]);
      int patch = Integer.valueOf(versionInfo[2]);
      String snapshotInfo = versionInfo.length == 3 ? null : versionInfo[3];
      return new Version(major, minor, patch, snapshotInfo, MavenProperties.GROUP_ID,
          MavenProperties.ARTIFACT_ID);
    } catch (Exception e) {
      return Version.unknownVersion();
    }
  }

}
