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

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializationConfig;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter;
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier;

public class EncryptedJsonSerializer extends JsonSerializer<Object> {

  private JsonSerializer<Object> baseSer;
  private EncryptionService<EncryptedJson> service;
  private Encrypted annotation;

  public EncryptedJsonSerializer(EncryptionService<EncryptedJson> service, Encrypted annotation,
      JsonSerializer<Object> baseSer) {
    this.service = service;
    this.annotation = annotation;
    this.baseSer = baseSer;
  }

  @Override
  public void serialize(Object object, JsonGenerator generator, SerializerProvider provider)
      throws IOException, JsonProcessingException {

    StringWriter writer = new StringWriter();
    JsonGenerator nestedGenerator = generator.getCodec().getFactory().createGenerator(writer);
    if (baseSer == null) {
      provider.defaultSerializeValue(object, nestedGenerator);
    } else {
      baseSer.serialize(object, nestedGenerator, provider);
    }
    nestedGenerator.close();
    String value = writer.getBuffer().toString();
    EncryptedJson encrypted = service.encrypt(value, this.annotation.encoding());
    generator.writeObject(encrypted);
  }

  public static class Modifier extends BeanSerializerModifier {
    private Map<String, EncryptionService<EncryptedJson>> sourceMap = new LinkedHashMap<>();

    public Modifier() {
    }

    public Modifier withSource( String name, EncryptionService<EncryptedJson> source ) {
      sourceMap.put(name, source);
      return this;
    }
    
    // we do not need to override this.
    @Override
    public List<BeanPropertyWriter> changeProperties(SerializationConfig config,
        BeanDescription beanDesc, List<BeanPropertyWriter> beanProperties) {
      List<BeanPropertyWriter> newWriters = new ArrayList<BeanPropertyWriter>();
      for (BeanPropertyWriter writer : beanProperties) {
        Encrypted encrypted = writer.getAnnotation(Encrypted.class);
        if (encrypted == null) {
          newWriters.add(writer);
          continue;
        }

        String source = encrypted.source();
        EncryptionService<EncryptedJson> service = sourceMap.get(source);
        if( service == null ) {
          throw new IllegalArgumentException(String.format("No encryption key source defined for %s.", source));
        }

        JsonSerializer<Object> currentSer = writer.getSerializer();
        JsonSerializer<Object> encryptSer =
            new EncryptedJsonSerializer(service, encrypted, currentSer);
        newWriters.add(new EncryptedPropertyWriter(writer, encryptSer));
      }
      return newWriters;
    }

  }

  static class EncryptedPropertyWriter extends BeanPropertyWriter {

    public EncryptedPropertyWriter(BeanPropertyWriter toCopy, JsonSerializer<Object> deser) {
      super(toCopy);
      this._serializer = deser;
    }
  }

}
