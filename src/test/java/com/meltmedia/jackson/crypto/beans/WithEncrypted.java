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
package com.meltmedia.jackson.crypto.beans;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.builder.EqualsBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.meltmedia.jackson.crypto.Encrypted;

public class WithEncrypted {
  @Encrypted
  @JsonProperty
  public String stringValue;
  @Encrypted
  @JsonProperty
  int intValue;
  @Encrypted
  @JsonProperty
  Nested nestedValue;
  @Encrypted
  @JsonProperty
  List<String> listValue;
  @Encrypted
  @JsonProperty
  Map<String, String> mapValue;

  public WithEncrypted withStringValue(String stringValue) {
    this.stringValue = stringValue;
    return this;
  }

  public WithEncrypted withIntValue(int intValue) {
    this.intValue = intValue;
    return this;
  }

  public WithEncrypted withNestedValue(Nested nestedValue) {
    this.nestedValue = nestedValue;
    return this;
  }

  public WithEncrypted withListValue(List<String> listValue) {
    this.listValue = listValue;
    return this;
  }

  public WithEncrypted withMapValue(Map<String, String> mapValue) {
    this.mapValue = mapValue;
    return this;
  }

  public boolean equals(Object o) {
    return EqualsBuilder.reflectionEquals(this, o, true);
  }
}