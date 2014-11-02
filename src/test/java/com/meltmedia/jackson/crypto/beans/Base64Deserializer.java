package com.meltmedia.jackson.crypto.beans;

import java.io.IOException;
import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.ResolvableDeserializer;

public class Base64Deserializer extends JsonDeserializer<String>
    implements ContextualDeserializer, ResolvableDeserializer {

  Base64 decoder = new Base64();

  @Override
  public String deserialize(JsonParser parser, DeserializationContext arg1) throws IOException,
      JsonProcessingException {

    byte[] decoded = decoder.decode(parser.readValueAs(String.class));
    return new String(decoded, "UTF-8");
  }

  @Override
  public void resolve(DeserializationContext arg0) throws JsonMappingException {
  }

  @Override
  public JsonDeserializer<?> createContextual(DeserializationContext arg0, BeanProperty arg1)
      throws JsonMappingException {
    return this;
  }

}
