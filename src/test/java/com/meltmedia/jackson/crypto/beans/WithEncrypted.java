package com.meltmedia.jackson.crypto.beans;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.builder.EqualsBuilder;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.meltmedia.jackson.crypto.Encrypted;


public class WithEncrypted {
	@Encrypted
	@JsonProperty
	String stringValue;
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
	
	public WithEncrypted withStringValue( String stringValue ) {
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
	
	public boolean equals( Object o ) {
		return EqualsBuilder.reflectionEquals(this, o, true);
	}
}