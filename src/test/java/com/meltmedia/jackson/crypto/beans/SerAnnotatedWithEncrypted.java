package com.meltmedia.jackson.crypto.beans;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.meltmedia.jackson.crypto.Encrypted;

public class SerAnnotatedWithEncrypted extends ReflectiveObject {
  @JsonProperty
  @JsonSerialize(using = Base64Serializer.class)
  @Encrypted
  public String value;

  public SerAnnotatedWithEncrypted withValue(String value) {
    this.value = value;
    return this;
  }
}
