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

  EncryptionService<EncryptedJson> service;

  public CryptoModule(EncryptionService<EncryptedJson> service) {
    this.service = service;
  }

  @Override
  public String getModuleName() {
    return "JacksonCrypto";
  }

  @Override
  public void setupModule(SetupContext context) {
    context.addBeanSerializerModifier(new EncryptedJsonSerializer.Modifier(service));
    context.addBeanDeserializerModifier(new EncryptedJsonDeserializer.Modifier(service));
  }

  @Override
  public Version version() {
    // TODO: add version information from classpath.
    return Version.unknownVersion();
  }

}
