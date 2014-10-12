package com.meltmedia.jackson.crypto;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Deserializer for encrypted configuration blocks.
 * 
 * @author Christian Trimble
 */
@SuppressWarnings("serial")
public class EncryptedConfigurationDeserializer extends TransformingDeserializer<EncryptedConfiguration>
{
  public EncryptedConfigurationDeserializer() {
    super(EncryptedConfiguration.class);
  }

  public EncryptedConfigurationDeserializer( BeanProperty property ) {
    super(EncryptedConfiguration.class, property);
  }

  @Override
  protected Object transform( EncryptedConfiguration intermediate, ObjectMapper mapper, DeserializationContext ctxt ) throws IOException,
    JsonProcessingException {
    try {
      String value = ConfigurationEncryptionService.getCipher().decrypt(intermediate, "UTF-8");
      return mapper.readValue(value, targetType);
    } catch( EncryptionException e ) {
      throw new IOException(String.format("could not decrypt value %s::%s", property.getMember().getDeclaringClass().getSimpleName(), property.getName()), e);
    }
  }
}
