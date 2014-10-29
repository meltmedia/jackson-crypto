package com.meltmedia.jackson.crypto;

import javax.validation.Validation;
import javax.validation.ValidationException;
import javax.validation.Validator;

import com.fasterxml.jackson.databind.ObjectMapper;

public class Defaults {
	public static final int KEY_LENGTH = 256;
	public static final int KEY_STRETCH_ITERATIONS = 2000;
	
	  /**
	   * Creates a default validator, if the supplied validator is null.
	   */
	  public static Validator defaultValidator(Validator validator) {
		  if( validator != null ) return validator;
	    try {
	      return Validation.buildDefaultValidatorFactory().getValidator();
	    }
	    catch( ValidationException ve ) {
	      throw new RuntimeException("cannot create dafault validator", ve);
	    }
	  }
	  
	  public static ObjectMapper defaultObjectMapper( ObjectMapper mapper ) {
		  if( mapper != null ) return mapper;
		  return new ObjectMapper();
	  }
}
