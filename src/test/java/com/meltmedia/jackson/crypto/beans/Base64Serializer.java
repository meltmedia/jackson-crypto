package com.meltmedia.jackson.crypto.beans;

import java.io.IOException;
import org.apache.commons.codec.binary.Base64;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.ContextualSerializer;
import com.fasterxml.jackson.databind.ser.ResolvableSerializer;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

public class Base64Serializer extends StdSerializer<String>
    implements ContextualSerializer, ResolvableSerializer {

  Base64 encoder = new Base64();

  protected Base64Serializer() {
    super(String.class);
  }

  @Override
  public void serialize(String value, JsonGenerator jgen, SerializerProvider provider)
      throws IOException, JsonGenerationException {
    if (value == null) {
      jgen.writeNull();
    } else {
      jgen.writeString(encoder.encodeToString(value.getBytes()));
    }
  }

  @Override
  public void resolve(SerializerProvider arg0) throws JsonMappingException {

  }

  @Override
  public JsonSerializer<?> createContextual(SerializerProvider arg0, BeanProperty arg1)
      throws JsonMappingException {
    return this;
  }

}
