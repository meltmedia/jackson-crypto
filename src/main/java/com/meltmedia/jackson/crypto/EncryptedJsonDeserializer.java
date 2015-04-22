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
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.BeanDescription;
import com.fasterxml.jackson.databind.BeanProperty;
import com.fasterxml.jackson.databind.DeserializationConfig;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.deser.BeanDeserializerBuilder;
import com.fasterxml.jackson.databind.deser.BeanDeserializerModifier;
import com.fasterxml.jackson.databind.deser.ContextualDeserializer;
import com.fasterxml.jackson.databind.deser.SettableBeanProperty;

public class EncryptedJsonDeserializer extends JsonDeserializer<Object>
    implements ContextualDeserializer {

  private EncryptionService service;
  private JsonDeserializer<Object> baseDeser;
  private Encrypted annotation;
  private BeanProperty property;

  public EncryptedJsonDeserializer(EncryptionService service, Encrypted annotation,
      JsonDeserializer<Object> baseDeser) {
    this.service = service;
    this.annotation = annotation;
    this.baseDeser = baseDeser;
  }

  public EncryptedJsonDeserializer(EncryptionService service, Encrypted encrypt,
      JsonDeserializer<Object> wrapped, BeanProperty property) {
    this.service = service;
    this.annotation = encrypt;
    this.baseDeser = wrapped;
    this.property = property;
  }

  @Override
  public Object deserialize(JsonParser parser, DeserializationContext context) throws IOException,
      JsonProcessingException {
    JsonDeserializer<?> deser = baseDeser;
    if (deser instanceof ContextualDeserializer) {
      deser = ((ContextualDeserializer) deser).createContextual(context, property);
    }
    return service.decrypt(parser, deser, context, property.getType());
  }

  @Override
  public JsonDeserializer<?> createContextual(DeserializationContext context, BeanProperty property)
      throws JsonMappingException {
    return new EncryptedJsonDeserializer(service, annotation, baseDeser, property);
  }

  public static class Modifier extends BeanDeserializerModifier {
    private Map<String, EncryptionService> sourceMap = new LinkedHashMap<>();

    public Modifier() {
    }

    public Modifier addSource(EncryptionService source) {
      sourceMap.put(source.getName(), source);
      return this;
    }

    @Override
    public BeanDeserializerBuilder updateBuilder(DeserializationConfig config,
        BeanDescription beanDesc, BeanDeserializerBuilder builder) {
      Iterator<SettableBeanProperty> beanPropertyIterator = builder.getProperties();
      while (beanPropertyIterator.hasNext()) {
        SettableBeanProperty settableBeanProperty = beanPropertyIterator.next();
        Encrypted encrypted = settableBeanProperty.getAnnotation(Encrypted.class);
        if (encrypted == null)
          continue;

        String source = encrypted.source();
        EncryptionService service = sourceMap.get(source);
        if (service == null) {
          throw new IllegalArgumentException(String.format(
              "No encryption key source defined for %s.", source));
        }
        JsonDeserializer<Object> current = settableBeanProperty.getValueDeserializer();
        builder.addOrReplaceProperty(settableBeanProperty
            .withValueDeserializer(new EncryptedJsonDeserializer(service, encrypted, current)),
            true);
      }
      return builder;
    }

  }
}
