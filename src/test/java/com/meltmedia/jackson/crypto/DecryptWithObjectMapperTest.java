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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.TreeTraversingParser;
import com.meltmedia.jackson.crypto.beans.DeserAnnotatedWithEncrypted;
import com.meltmedia.jackson.crypto.beans.SerAnnotatedWithEncrypted;
import com.meltmedia.jackson.crypto.beans.WithEncrypted;

public class DecryptWithObjectMapperTest {

  ObjectMapper mapper;
  EncryptionService<EncryptedJson> service;

  @Before
  public void setUp() {
    Map<String, char[]> keys = new HashMap<String, char[]>();
    keys.put("current", "current secret".toCharArray());
    keys.put("old", "old secret".toCharArray());

    mapper = new ObjectMapper();

    service = EncryptionService.builder()
          .withPassphraseLookup(Functions.passphraseFunction(keys))
          .withEncryptedJsonSupplier(Functions.encryptedJsonSupplier("current"))
          .withObjectMapper(mapper)
            .build();

    mapper.registerModule(new CryptoModule().withSource(service));
  }

  @Test
  public void shouldRoundTrip() throws IOException {
    WithEncrypted withEncrypted = new WithEncrypted().withStringValue("some secret");

    String value = mapper.writeValueAsString(withEncrypted);

    WithEncrypted decrypted = mapper.readValue(value, WithEncrypted.class);

    assertThat("the original class and the decrypted class are the same", decrypted,
        equalTo(withEncrypted));
  }

  @Test
  public void shouldDecryptWithDeserializerAnnotation() throws JsonParseException,
      JsonMappingException, JsonProcessingException, IOException {
    SerAnnotatedWithEncrypted toEncrypt = new SerAnnotatedWithEncrypted().withValue("some value");

    DeserAnnotatedWithEncrypted roundTrip =
        mapper.readValue(mapper.writeValueAsString(toEncrypt), DeserAnnotatedWithEncrypted.class);

    assertThat(roundTrip.value, equalTo("some value"));

  }
  
  @Test
  public void shouldDecryptWithoutObjectCodec() throws IOException {
    WithEncrypted withEncrypted = new WithEncrypted().withStringValue("some secret");

    JsonNode node = mapper.convertValue(withEncrypted, JsonNode.class);
    
    WithEncrypted result = mapper.copy().readValue(new TreeTraversingParser(node), WithEncrypted.class);
  }

}
