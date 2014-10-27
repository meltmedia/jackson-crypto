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
public class EncryptedJsonDeserializer extends TransformingDeserializer<EncryptedJson>
{
  public EncryptedJsonDeserializer() {
    super(EncryptedJson.class);
  }

  public EncryptedJsonDeserializer( BeanProperty property ) {
    super(EncryptedJson.class, property);
  }

  @Override
  protected Object transform( EncryptedJson intermediate, ObjectMapper mapper, DeserializationContext ctxt ) throws IOException,
    JsonProcessingException {
    try {
      String value = EnvironmentEncryptionService.getCipher().decrypt(intermediate, "UTF-8");
      return mapper.readValue(value, targetType);
    } catch( EncryptionException e ) {
      throw new IOException(String.format("could not decrypt value %s::%s", property.getMember().getDeclaringClass().getSimpleName(), property.getName()), e);
    }
  }
}
