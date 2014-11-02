package com.meltmedia.jackson.crypto.beans;

import org.apache.commons.lang3.builder.EqualsBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Nested {
	@JsonProperty
  String value;
  
  public Nested withValue( String value ) {
	  this.value = value;
	  return this;
  }
  
	
  public boolean equals( Object o ) {
    return EqualsBuilder.reflectionEquals(this, o, true);
  }
}