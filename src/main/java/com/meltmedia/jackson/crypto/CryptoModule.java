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
