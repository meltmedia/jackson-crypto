package com.meltmedia.jackson.crypto.beans;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.meltmedia.jackson.crypto.Encrypted;

public class DeserAnnotatedWithEncrypted extends ReflectiveObject {
  @JsonProperty
  @JsonDeserialize(using = Base64Deserializer.class)
  @Encrypted
  public String value;

  public DeserAnnotatedWithEncrypted withValue(String value) {
    this.value = value;
    return this;
  }
}
