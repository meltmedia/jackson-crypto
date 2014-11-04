package com.meltmedia.jackson.crypto.beans;

import org.apache.commons.lang3.builder.EqualsBuilder;

public class ReflectiveObject {

  public boolean equals(Object o) {
    return EqualsBuilder.reflectionEquals(this, o, true);
  }
}
