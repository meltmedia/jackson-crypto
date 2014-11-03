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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.meltmedia.jackson.crypto.beans.Nested;
import com.meltmedia.jackson.crypto.beans.SerAnnotatedWithEncrypted;
import com.meltmedia.jackson.crypto.beans.WithEncrypted;

public class EncryptWithObjectMapperTest {

  ObjectMapper mapper;
  EncryptionService<EncryptedJson> service;

  @Before
  public void setUp() {
    Map<String, char[]> keys = new HashMap<String, char[]>();
    keys.put("current", "current secret".toCharArray());
    keys.put("old", "old secret".toCharArray());
    DynamicEncryptionConfiguration config = new DynamicEncryptionConfiguration();
    config.setCurrentKey("current");
    config.setKeys(keys);

    mapper = new ObjectMapper();

    service =
        EncryptionService.builder().withPassphraseLookup(config.passphraseFunction())
            .withEncryptedJsonSupplier(config.encryptedJsonSupplier()).withObjectMapper(mapper)
            .build();

    mapper.registerModule(new CryptoModule(service));
  }

  @Test
  public void shouldEncryptString() throws IOException {
    WithEncrypted toEncrypt = new WithEncrypted().withStringValue("some value");

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    assertThat("has nested value", encrypted.at("/stringValue/value").isNull(), equalTo(false));
    assertThat("nested value is encrypted", encrypted.at("/stringValue/value").asText(),
        not(containsString("some value")));

    EncryptedJson result = mapper.convertValue(encrypted.get("stringValue"), EncryptedJson.class);
    JsonNode roundTrip = service.decryptAs(result, "UTF-8", JsonNode.class);

    assertThat(roundTrip.asText(), equalTo("some value"));
  }

  @Test
  public void shouldEncryptInteger() throws IOException {
    WithEncrypted toEncrypt = new WithEncrypted().withIntValue(10);

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    assertThat("has nested value", encrypted.at("/intValue/value").isNull(), equalTo(false));
    assertThat("nested value is encrypted", encrypted.at("/intValue/value").asText(),
        not(containsString("10")));
  }

  @Test
  public void shouldEncryptNested() throws IOException {
    WithEncrypted toEncrypt =
        new WithEncrypted().withNestedValue(new Nested().withValue("some value"));

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    assertThat("has nested value", encrypted.at("/nestedValue/value").isNull(), equalTo(false));
    assertThat("nested value is encrypted", encrypted.at("/nestedValue/value").asText(),
        not(containsString("some value")));
  }

  @Test
  public void shouldEncryptList() throws IOException {
    WithEncrypted toEncrypt = new WithEncrypted().withListValue(Arrays.asList("value1", "value2"));

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    assertThat("has nested value", encrypted.at("/listValue/value").isNull(), equalTo(false));
    assertThat("nested value is encrypted", encrypted.at("/listValue/value").asText(),
        not(containsString("value")));
  }

  @Test
  public void shouldEncryptMap() throws IOException {
    Map<String, String> mapValue = new HashMap<String, String>();
    mapValue.put("key1", "value1");
    mapValue.put("key2", "value2");
    WithEncrypted toEncrypt = new WithEncrypted().withMapValue(mapValue);

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    assertThat("has nested value", encrypted.at("/listValue/value").isNull(), equalTo(false));
    assertThat("nested value is encrypted", encrypted.at("/listValue/value").asText(),
        not(containsString("value")));
  }

  @Test
  public void shouldEncryptWithSerializerAnnotation() throws JsonParseException,
      JsonMappingException, JsonProcessingException, IOException {
    SerAnnotatedWithEncrypted toEncrypt = new SerAnnotatedWithEncrypted().withValue("some value");

    ObjectNode encrypted = mapper.readValue(mapper.writeValueAsString(toEncrypt), ObjectNode.class);

    EncryptedJson result = mapper.convertValue(encrypted.get("value"), EncryptedJson.class);
    JsonNode roundTrip = service.decryptAs(result, "UTF-8", JsonNode.class);

    assertThat(roundTrip.asText(), equalTo("c29tZSB2YWx1ZQ=="));

  }
}
